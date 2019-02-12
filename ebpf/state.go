package ebpf

import (
	"bytes"
	"sync"
	"time"

	log "github.com/cihub/seelog"
)

var _ NetworkState = &networkState{}

const (
	// DEBUGCLIENT is the ClientID for debugging
	DEBUGCLIENT          = "-1"
	defaultClientExpiry  = 2 * time.Minute
	defaultCleanInterval = 30 * time.Second
)

// NetworkState takes care of handling the logic for:
// - closed connections
// - sent and received bytes per connection
type NetworkState interface {
	Connections(clientID string) []ConnectionStats // Returns the list of connections for the given client
	StoreConnections(conns []ConnectionStats)      // Store new connections in state
	StoreClosedConnection(conn ConnectionStats)    // Store a new closed connection
	RemoveClient(clientID string)                  // Stop tracking stateful data for the given client
	RemoveDuplicates(conns map[string]*ConnectionStats, closedConns []ConnectionStats) []ConnectionStats
}

type sentRecvStats struct {
	totalSent uint64
	lastSent  uint64

	totalRecv uint64
	lastRecv  uint64

	totalRetransmits uint32
	lastRetransmits  uint32
}

type client struct {
	lastFetch time.Time
	// We only store the pointer to the connection for each client
	// When it's cleaned up by all the clients the underlying connection will get GC'ed
	// However this restrict us from modifying the underlying connection (otherwise it
	// will be modified for each client
	closedConnections   map[string]*ConnectionStats
	overrideConnections map[string]sentRecvStats
	stats               map[string]*sentRecvStats
}

type networkState struct {
	sync.Mutex

	clients     map[string]*client
	connections map[string]*ConnectionStats

	// Shared buffer
	buf *bytes.Buffer

	cleanInterval time.Duration
	clientExpiry  time.Duration
}

// NewDefaultNetworkState creates a new network state with default settings
func NewDefaultNetworkState() NetworkState {
	return NewNetworkState(defaultCleanInterval, defaultClientExpiry)
}

// NewNetworkState creates a new network state
func NewNetworkState(cleanInterval time.Duration, clientExpiry time.Duration) NetworkState {
	ns := &networkState{
		clients:       map[string]*client{},
		connections:   map[string]*ConnectionStats{},
		cleanInterval: cleanInterval,
		clientExpiry:  clientExpiry,
		buf:           &bytes.Buffer{},
	}

	// Start tracking expiry time for clients
	go func() {
		for now := range time.NewTicker(ns.cleanInterval).C {
			ns.removeExpiredClients(now)
		}
	}()

	return ns
}

func (ns *networkState) getClients() []string {
	ns.Lock()
	defer ns.Unlock()
	clients := make([]string, 0, len(ns.clients))

	for id := range ns.clients {
		clients = append(clients, id)
	}

	return clients
}

// Connections returns the connections for the given client
// If the client is not registered yet, we register it and return the connections we have in the global state
// Otherwise we return both the connections with last stats and the closed connections for this client
func (ns *networkState) Connections(id string) []ConnectionStats {
	ns.Lock()
	defer ns.Unlock()

	// If its the first time we've seen this client, use global state as connection set
	if ok := ns.newClient(id); !ok {
		conns := make([]ConnectionStats, 0, len(ns.connections))
		for _, c := range ns.connections {
			conns = append(conns, *c)
		}
		return conns
	}

	return ns.RemoveDuplicates(ns.getConnections(id), ns.closedConns(id))
}

// StoreConnections stores the provided list of connections in the global state
func (ns *networkState) StoreConnections(conns []ConnectionStats) {
	// Update connections
	ns.Lock()
	defer ns.Unlock()

	// Flush the previous map
	ns.connections = map[string]*ConnectionStats{}

	for _, c := range conns {
		key, err := c.ByteKey(ns.buf)
		if err != nil {
			log.Errorf("%s", err)
			continue
		}

		ns.connections[string(key)] = &c

		// Check if some clients don't have the same connection still stored as closed
		// if they do remove it from the closed connections and store in the override connections
		// For later aggregation
		for _, client := range ns.clients {
			if prev, ok := client.closedConnections[string(key)]; ok {
				// Entry is already here, add the old connection to override connections
				// For later aggregation
				newOverride := statsFromConn(*prev)
				if override, ok := client.overrideConnections[string(key)]; ok {
					// If we already have an override aggregate the two overrides
					newOverride = aggregateStats(override, newOverride)
				}
				client.overrideConnections[string(key)] = newOverride
				delete(client.closedConnections, string(key))
			}
		}
	}
}

// StoreClosedConnection stores the given connection for every client
func (ns *networkState) StoreClosedConnection(conn ConnectionStats) {
	ns.Lock()
	defer ns.Unlock()

	key, err := conn.ByteKey(ns.buf)
	if err != nil {
		log.Errorf("%s", err)
		return
	}

	for _, client := range ns.clients {
		if prev, ok := client.closedConnections[string(key)]; ok {
			// Entry is already here, add the old connection to override connections
			// For later aggregation
			newOverride := statsFromConn(*prev)
			if override, ok := client.overrideConnections[string(key)]; ok {
				// If we already have an override aggregate the two overrides
				newOverride = aggregateStats(override, newOverride)
			}
			client.overrideConnections[string(key)] = newOverride
		}

		// We only store the pointer to the connection, when it will be cleared for each client it will get GCed
		client.closedConnections[string(key)] = &conn
	}
}

// closedConns returns the closed connections for the given client and takes care of updating last fetch
// the provided client is supposed to exist
func (ns *networkState) closedConns(clientID string) []ConnectionStats {
	client := ns.clients[clientID]
	conns := make([]ConnectionStats, 0, len(client.closedConnections))

	for key, conn := range client.closedConnections {
		c := *conn

		// First check if we have an override stored
		// If we do aggregate it and delete the override
		if override, ok := client.overrideConnections[key]; ok {
			aggregateConnAndStat(&c, &override)
			delete(client.overrideConnections, key)
		}

		if stats, ok := client.stats[key]; ok {
			c.LastSentBytes = stats.lastSent + c.MonotonicSentBytes - stats.totalSent
			c.LastRecvBytes = stats.lastRecv + c.MonotonicRecvBytes - stats.totalRecv
			c.LastRetransmits = stats.lastRetransmits + c.MonotonicRetransmits - stats.totalRetransmits
			delete(client.stats, key)
		} else {
			c.LastSentBytes = c.MonotonicSentBytes
			c.LastRecvBytes = c.MonotonicRecvBytes
			c.LastRetransmits = c.MonotonicRetransmits
		}

		conns = append(conns, c)
	}

	// Flush closed connections for this client
	client.closedConnections = map[string]*ConnectionStats{}

	return conns
}

// newClient creates a new client and returns true if the given client already exists
func (ns *networkState) newClient(clientID string) bool {
	if _, ok := ns.clients[clientID]; ok {
		return true
	}

	ns.clients[clientID] = &client{
		lastFetch:           time.Now(),
		stats:               map[string]*sentRecvStats{},
		closedConnections:   map[string]*ConnectionStats{},
		overrideConnections: map[string]sentRecvStats{},
	}
	return false
}

// getConnections return the connections and takes care of updating their last stats
func (ns *networkState) getConnections(id string) map[string]*ConnectionStats {
	// Update client's last fetch time
	client := ns.clients[id]
	client.lastFetch = time.Now()

	// Update send/recv bytes stats
	for key, conn := range ns.connections {
		stats, ok := client.stats[key]
		if !ok {
			stats = &sentRecvStats{}
			client.stats[key] = stats
		}

		// If we have an override for this conn for this client, aggregate the conn
		if override, ok := client.overrideConnections[key]; ok {
			aggregateConnAndStat(conn, &override)
		}

		stats.lastSent = conn.MonotonicSentBytes - stats.totalSent
		stats.lastRecv = conn.MonotonicRecvBytes - stats.totalRecv
		stats.lastRetransmits = conn.MonotonicRetransmits - stats.totalRetransmits

		conn.LastSentBytes = stats.lastSent
		conn.LastRecvBytes = stats.lastRecv
		conn.LastRetransmits = stats.lastRetransmits

		stats.totalSent = conn.MonotonicSentBytes
		stats.totalRecv = conn.MonotonicRecvBytes
		stats.totalRetransmits = conn.MonotonicRetransmits
	}

	return ns.connections
}

func (ns *networkState) RemoveClient(clientID string) {
	ns.Lock()
	defer ns.Unlock()
	delete(ns.clients, clientID)
}

func (ns *networkState) removeExpiredClients(now time.Time) {
	ns.Lock()
	defer ns.Unlock()

	for id, c := range ns.clients {
		if c.lastFetch.Add(ns.clientExpiry).Before(now) {
			delete(ns.clients, id)
		}
	}
}

// aggregateConnectionAndStats aggregates s into c
func aggregateConnAndStat(cs *ConnectionStats, stats *sentRecvStats) {
	cs.LastSentBytes += stats.lastSent
	cs.MonotonicSentBytes += stats.totalSent
	cs.LastRecvBytes += stats.lastRecv
	cs.MonotonicRecvBytes += stats.totalRecv
	cs.LastRetransmits += stats.lastRetransmits
	cs.MonotonicRetransmits += stats.totalRetransmits
}

// aggregateStats returns an aggregation of two stats
func aggregateStats(s1, s2 sentRecvStats) sentRecvStats {
	return sentRecvStats{
		lastSent:         s1.lastSent + s2.lastSent,
		lastRecv:         s1.lastRecv + s2.lastRecv,
		lastRetransmits:  s1.lastRetransmits + s2.lastRetransmits,
		totalSent:        s1.totalSent + s2.totalSent,
		totalRecv:        s1.totalRecv + s2.totalRecv,
		totalRetransmits: s1.totalRetransmits + s2.totalRetransmits,
	}
}

func statsFromConn(conn ConnectionStats) sentRecvStats {
	return sentRecvStats{
		lastSent:         conn.LastSentBytes,
		lastRecv:         conn.LastRecvBytes,
		lastRetransmits:  conn.LastRetransmits,
		totalSent:        conn.MonotonicSentBytes,
		totalRecv:        conn.MonotonicRecvBytes,
		totalRetransmits: conn.MonotonicRetransmits,
	}
}

// RemoveDuplicates takes a list of opened connections and a list of closed connections and returns a list of connections without duplicates
// giving priority to closed connections
func (ns *networkState) RemoveDuplicates(conns map[string]*ConnectionStats, closedConns []ConnectionStats) []ConnectionStats {
	connections := make([]ConnectionStats, 0)

	seen := map[string]struct{}{}

	// Start with the closed connections
	for _, c := range closedConns {
		key, err := c.ByteKey(ns.buf)
		if err != nil {
			log.Errorf("%s", err)
			continue
		}

		if _, ok := seen[string(key)]; !ok {
			connections = append(connections, c)
			seen[string(key)] = struct{}{}
		}
	}

	for key, c := range conns {
		if _, ok := seen[key]; !ok {
			// Note: We don't need to add to `seen` conn's list is all unique (by virtue of using the BPF map key)
			connections = append(connections, *c)
		}
	}

	return connections
}
