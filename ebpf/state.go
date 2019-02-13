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
	DEBUGCLIENT           = "-1"
	defaultExpiry         = 2 * time.Minute
	defaultClientInterval = 30 * time.Second
)

// NetworkState takes care of handling the logic for:
// - closed connections
// - sent and received bytes per connection
type NetworkState interface {
	// Connections returns the list of connections for the given client when provided the latest set of active connections
	Connections(clientID string, latestConns []ConnectionStats) []ConnectionStats

	// StoreClosedConnection stores a new closed connection
	StoreClosedConnection(conn ConnectionStats)

	// RemoveClient stops tracking stateful data for a given client
	RemoveClient(clientID string)

	// RemoveDuplicates removes duplicate connections from active and closed sets of connections, preferring closed.
	RemoveDuplicates(active map[string]*ConnectionStats, closed []ConnectionStats) []ConnectionStats
}

type sentRecvStats struct {
	totalSent uint64
	lastSent  uint64

	totalRecv uint64
	lastRecv  uint64

	totalRetransmits uint32
	lastRetransmits  uint32

	lastUpdate time.Time
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
	buf *bytes.Buffer // Shared buffer

	clients map[string]*client

	clientInterval time.Duration
	expiry         time.Duration
}

// NewDefaultNetworkState creates a new network state with default settings
func NewDefaultNetworkState() NetworkState {
	return NewNetworkState(defaultClientInterval, defaultExpiry)
}

// NewNetworkState creates a new network state
func NewNetworkState(clientInterval time.Duration, expiry time.Duration) NetworkState {
	ns := &networkState{
		clients:        map[string]*client{},
		clientInterval: clientInterval,
		expiry:         expiry,
		buf:            &bytes.Buffer{},
	}

	// Start tracking expiry time for clients
	go func() {
		count := uint64(0)
		for now := range time.NewTicker(ns.clientInterval).C {
			// Every 10 ticks, lets also check for any outdated stats objects to remove
			count++
			removeExpiredStats := count%10 == 0
			ns.removeExpiredClients(now, removeExpiredStats)
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
func (ns *networkState) Connections(id string, latestConns []ConnectionStats) []ConnectionStats {
	ns.Lock()
	defer ns.Unlock()

	connsByKey := ns.updateActiveConnections(latestConns)

	// If its the first time we've seen this client, use global state as connection set
	if ok := ns.newClient(id); !ok {
		return latestConns
	}

	// Update connections with relevant up-to-date stats for client
	ns.updateConnectionsForClient(id, connsByKey)

	return ns.RemoveDuplicates(connsByKey, ns.closedConns(id))
}

// updateActiveConnections processes new active connections, updating internal state and returning a map of
// connections by key.
func (ns *networkState) updateActiveConnections(conns []ConnectionStats) map[string]*ConnectionStats {
	connsByKey := make(map[string]*ConnectionStats, len(conns))
	now := time.Now()

	for i, c := range conns {
		key, err := c.ByteKey(ns.buf)
		if err != nil {
			log.Warn("failed to create byte key: %s", err)
			continue
		}

		connsByKey[string(key)] = &conns[i]

		// Check if some clients don't have the same connection still stored as closed
		// if they do remove it from the closed connections and store in the override connections
		// For later aggregation
		for _, client := range ns.clients {
			if prev, ok := client.closedConnections[string(key)]; ok {
				// Entry is already here, add the old connection to override connections
				// For later aggregation
				newOverride := statsFromConn(*prev, now)
				if override, ok := client.overrideConnections[string(key)]; ok {
					// If we already have an override aggregate the two overrides
					newOverride = aggregateStats(override, newOverride, now)
				}
				client.overrideConnections[string(key)] = newOverride
				delete(client.closedConnections, string(key))
			}
		}
	}
	return connsByKey
}

// StoreClosedConnection stores the given connection for every client
func (ns *networkState) StoreClosedConnection(conn ConnectionStats) {
	ns.Lock()
	defer ns.Unlock()

	now := time.Now()
	key, err := conn.ByteKey(ns.buf)
	if err != nil {
		log.Warn("failed to create byte key: %s", err)
		return
	}

	for _, client := range ns.clients {
		if prev, ok := client.closedConnections[string(key)]; ok {
			// Entry is already here, add the old connection to override connections
			// For later aggregation
			newOverride := statsFromConn(*prev, now)
			if override, ok := client.overrideConnections[string(key)]; ok {
				// If we already have an override aggregate the two overrides
				newOverride = aggregateStats(override, newOverride, now)
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
			c.LastSentBytes = c.MonotonicSentBytes - stats.totalSent
			c.LastRecvBytes = c.MonotonicRecvBytes - stats.totalRecv
			c.LastRetransmits = c.MonotonicRetransmits - stats.totalRetransmits
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

// updateConnectionsForClient return the connections and takes care of updating their last stats
func (ns *networkState) updateConnectionsForClient(id string, connByKey map[string]*ConnectionStats) {
	now := time.Now()
	client := ns.clients[id]
	client.lastFetch = now

	// Update send/recv bytes stats
	for key, conn := range connByKey {
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

		stats.lastUpdate = now
	}
}

func (ns *networkState) RemoveClient(clientID string) {
	ns.Lock()
	defer ns.Unlock()
	delete(ns.clients, clientID)
}

func (ns *networkState) removeExpiredClients(now time.Time, removeExpiredStats bool) {
	ns.Lock()
	defer ns.Unlock()

	deletedStats := 0
	for id, c := range ns.clients {
		if c.lastFetch.Add(ns.expiry).Before(now) {
			delete(ns.clients, id)
		} else if removeExpiredStats { // Look for inactive stats objects and remove them
			deletedStats += ns.removeExpiredStats(c, now)
		}
	}

	if deletedStats > 0 {
		log.Debugf("removed %d expired stats objects in %d", deletedStats, time.Now().Sub(now))
	}
}

func (ns *networkState) removeExpiredStats(c *client, now time.Time) int {
	expired, removed := make([]string, 0), 0

	// Expired stats
	for key, s := range c.stats {
		if s.lastUpdate.Add(ns.expiry).Before(now) {
			expired = append(expired, key)
			removed++
		}
	}

	for _, key := range expired {
		delete(c.stats, key)
	}

	// Expired stat overrides
	expired = expired[:0]
	for key, s := range c.overrideConnections {
		if s.lastUpdate.Add(ns.expiry).Before(now) {
			expired = append(expired, key)
			removed++
		}
	}

	for _, key := range expired {
		delete(c.overrideConnections, key)
	}

	return removed
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
func aggregateStats(s1, s2 sentRecvStats, now time.Time) sentRecvStats {
	return sentRecvStats{
		lastSent:         s1.lastSent + s2.lastSent,
		lastRecv:         s1.lastRecv + s2.lastRecv,
		lastRetransmits:  s1.lastRetransmits + s2.lastRetransmits,
		totalSent:        s1.totalSent + s2.totalSent,
		totalRecv:        s1.totalRecv + s2.totalRecv,
		totalRetransmits: s1.totalRetransmits + s2.totalRetransmits,
		lastUpdate:       now,
	}
}

func statsFromConn(conn ConnectionStats, now time.Time) sentRecvStats {
	return sentRecvStats{
		lastSent:         conn.LastSentBytes,
		lastRecv:         conn.LastRecvBytes,
		lastRetransmits:  conn.LastRetransmits,
		totalSent:        conn.MonotonicSentBytes,
		totalRecv:        conn.MonotonicRecvBytes,
		totalRetransmits: conn.MonotonicRetransmits,
		lastUpdate:       now,
	}
}

// RemoveDuplicates takes a list of opened connections and a list of closed connections and returns a list of connections without duplicates
// giving priority to closed connections
func (ns *networkState) RemoveDuplicates(latest map[string]*ConnectionStats, closed []ConnectionStats) []ConnectionStats {
	connections := make([]ConnectionStats, 0)

	seen := map[string]struct{}{}

	// Start with the closed connections
	for _, c := range closed {
		key, err := c.ByteKey(ns.buf)
		if err != nil {
			log.Warn("failed to create byte key: %s", err)
			continue
		}

		if _, ok := seen[string(key)]; !ok {
			connections = append(connections, c)
			seen[string(key)] = struct{}{}
		}
	}

	for key, c := range latest {
		if _, ok := seen[key]; !ok {
			// Note: We don't need to add to `seen` conn's list is all unique (by virtue of using the BPF map key)
			connections = append(connections, *c)
		}
	}

	return connections
}
