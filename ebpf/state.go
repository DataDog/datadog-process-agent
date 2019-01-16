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
	defaultClientExpiry  = 5 * time.Minute
	defaultCleanInterval = 10 * time.Second
)

// NetworkState takes care of handling the logic for:
// - closed connections
// - sent and received bytes per connection
type NetworkState interface {
	Connections(clientID string) []ConnectionStats // Returns the list of connections for the given client
	StoreConnections(conns []ConnectionStats)      // Store new connections in state
	StoreClosedConnection(conn ConnectionStats)    // Store a new closed connection
	RemoveClient(clientID string)                  // Stop tracking stateful data for the given client
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

func (ns *networkState) Connections(id string) []ConnectionStats {
	// First time we see this client, use global state
	if old := ns.newClient(id); !old {
		ns.Lock()
		defer ns.Unlock()
		conns := make([]ConnectionStats, 0, len(ns.connections))
		for _, conn := range ns.connections {
			conns = append(conns, *conn)
		}
		return conns
	}

	return removeDuplicates(ns.getConnections(id), ns.closedConns(id))
}

func (ns *networkState) StoreConnections(conns []ConnectionStats) {
	// Update connections
	ns.Lock()
	defer ns.Unlock()

	// Flush the previous map
	ns.connections = map[string]*ConnectionStats{}

	buf := &bytes.Buffer{}
	for _, c := range conns {
		rawKey, err := c.ByteKey(buf)
		if err != nil {
			log.Errorf("%s", err)
			continue
		}
		key := string(rawKey)

		// copy to get pointer to struct
		c2 := c
		ns.connections[key] = &c2

		// Check if some clients don't have the same connection still stored as closed
		// if they do remove it from the closed connections and store in the override connections
		// For later aggregation
		for id := range ns.clients {
			if prev, ok := ns.clients[id].closedConnections[key]; ok {
				// Entry is already here, add the old connection to override connections
				// For later aggregation
				newOverride := statsFromConn(*prev)
				if override, ok := ns.clients[id].overrideConnections[key]; ok {
					// If we already have an override aggregate the two overrides
					newOverride = aggregateStats(override, newOverride)
				}
				ns.clients[id].overrideConnections[key] = newOverride
				delete(ns.clients[id].closedConnections, key)
			}
		}
	}
}

// StoreClosedConnection stores the given connection for every client
func (ns *networkState) StoreClosedConnection(conn ConnectionStats) {
	ns.Lock()
	defer ns.Unlock()

	rawKey, err := conn.ByteKey(&bytes.Buffer{})
	if err != nil {
		log.Errorf("%s", err)
		return
	}
	key := string(rawKey)

	for id := range ns.clients {
		if prev, ok := ns.clients[id].closedConnections[key]; ok {
			// Entry is already here, add the old connection to override connections
			// For later aggregation
			newOverride := statsFromConn(*prev)
			if override, ok := ns.clients[id].overrideConnections[key]; ok {
				// If we already have an override aggregate the two overrides
				newOverride = aggregateStats(override, newOverride)
			}
			ns.clients[id].overrideConnections[key] = newOverride
		}

		// We only store the pointer to the connection, when it will be cleared for each client it will get GCed
		ns.clients[id].closedConnections[key] = &conn
	}
}

// closedConns returns the closed connections for the given client and takes care of updating last fetch
// the provided client is supposed to exist
func (ns *networkState) closedConns(clientID string) []ConnectionStats {
	conns := []ConnectionStats{}

	ns.Lock()
	defer ns.Unlock()

	for key, conn := range ns.clients[clientID].closedConnections {
		// We dereference to avoid modifying the underlying connection
		// since it's shared with other clients
		c := *conn

		// First check if we have an override stored
		// If we do aggregate it and delete the override
		if override, ok := ns.clients[clientID].overrideConnections[key]; ok {
			aggregateConnAndStat(&c, override)
			delete(ns.clients[clientID].overrideConnections, key)
		}

		// Total defaults to 0 if it's not stored
		prev := sentRecvStats{}
		if _, ok := ns.clients[clientID].stats[key]; ok {
			prev = *ns.clients[clientID].stats[key]
			delete(ns.clients[clientID].stats, key)
		}

		// Update last stats
		c.LastSentBytes = prev.lastSent + c.MonotonicSentBytes - prev.totalSent
		c.LastRecvBytes = prev.lastRecv + c.MonotonicRecvBytes - prev.totalRecv
		c.LastRetransmits = prev.lastRetransmits + c.MonotonicRetransmits - prev.totalRetransmits
		conns = append(conns, c)
	}

	// Flush closed connections for this client
	ns.clients[clientID].closedConnections = map[string]*ConnectionStats{}
	return conns
}

// newClient creates a new client and returns true if the given client already exists
func (ns *networkState) newClient(clientID string) bool {
	ns.Lock()
	defer ns.Unlock()
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
func (ns *networkState) getConnections(id string) []ConnectionStats {
	ns.Lock()
	defer ns.Unlock()

	// Update client's last fetch time
	ns.clients[id].lastFetch = time.Now()

	conns := make([]ConnectionStats, 0, len(ns.connections))

	// Update send/recv bytes stats
	for key, conn := range ns.connections {
		// We dereference to avoid modifying the underlying connection
		// since it's shared with other clients
		c := *conn

		if _, old := ns.clients[id].stats[key]; !old {
			ns.clients[id].stats[key] = &sentRecvStats{}
		}

		// If we have an override for this conn for this client, aggregate the conn
		if override, ok := ns.clients[id].overrideConnections[key]; ok {
			aggregateConnAndStat(&c, override)
		}

		prev := ns.clients[id].stats[key]
		ns.clients[id].stats[key].lastSent = c.MonotonicSentBytes - prev.totalSent
		ns.clients[id].stats[key].lastRecv = c.MonotonicRecvBytes - prev.totalRecv
		ns.clients[id].stats[key].lastRetransmits = c.MonotonicRetransmits - prev.totalRetransmits

		c.LastSentBytes = prev.lastSent
		c.LastRecvBytes = prev.lastRecv
		c.LastRetransmits = prev.lastRetransmits

		ns.clients[id].stats[key].totalSent = c.MonotonicSentBytes
		ns.clients[id].stats[key].totalRecv = c.MonotonicRecvBytes
		ns.clients[id].stats[key].totalRetransmits = c.MonotonicRetransmits

		conns = append(conns, c)
	}

	return conns
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

// aggregateConnections aggregates c2 into c1, they should have the same key
func aggregateConnections(c1 *ConnectionStats, c2 ConnectionStats) {
	c1.LastSentBytes += c2.LastSentBytes
	c1.MonotonicSentBytes += c2.MonotonicSentBytes
	c1.LastRecvBytes += c2.LastRecvBytes
	c1.MonotonicRecvBytes += c2.MonotonicRecvBytes
	c1.LastRetransmits += c2.LastRetransmits
	c1.MonotonicRetransmits += c2.MonotonicRetransmits
}

// aggregateConnectionAndStats aggregates s into c
func aggregateConnAndStat(c1 *ConnectionStats, s sentRecvStats) {
	c1.LastSentBytes += s.lastSent
	c1.MonotonicSentBytes += s.totalSent
	c1.LastRecvBytes += s.lastRecv
	c1.MonotonicRecvBytes += s.totalRecv
	c1.LastRetransmits += s.lastRetransmits
	c1.MonotonicRetransmits += s.totalRetransmits
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

// removeDuplicates takes a list of opened connections and a list of closed connections and returns a list of connections without duplicates
// giving priority to closed connections
func removeDuplicates(conns []ConnectionStats, closedConns []ConnectionStats) []ConnectionStats {
	connections := []ConnectionStats{}

	seen := map[string]struct{}{}
	buf := &bytes.Buffer{}

	// Start with the closed connections
	for _, c := range append(closedConns, conns...) {
		rawKey, err := c.ByteKey(buf)
		if err != nil {
			log.Errorf("%s", err)
			continue
		}
		key := string(rawKey)

		if _, ok := seen[key]; !ok {
			connections = append(connections, c)
			seen[key] = struct{}{}
		}
	}

	return connections
}
