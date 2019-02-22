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

	// GetStats returns a map of statistics about the current network state
	GetStats() map[string]interface{}
}

type overrideStats struct {
	totalSent uint64
	lastSent  uint64

	totalRecv uint64
	lastRecv  uint64

	totalRetransmits uint32
	lastRetransmits  uint32

	lastUpdate time.Time
}

type stats struct {
	totalSent        uint64
	totalRecv        uint64
	totalRetransmits uint32

	lastUpdate time.Time
}

type client struct {
	lastFetch time.Time
	// We only store the pointer to the connection for each client
	// When it's cleaned up by all the clients the underlying connection will get GC'ed
	// However this restrict us from modifying the underlying connection (otherwise it
	// will be modified for each client
	closedConnections   map[string]*ConnectionStats
	overrideConnections map[string]overrideStats
	stats               map[string]*stats
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

	// Update active connections with relevant up-to-date stats for client
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

		// If any clients have this connection stored as recently-closed, then remove it from the closed connections
		// and store as stats override for better tracking.
		for _, client := range ns.clients {
			if prev, ok := client.closedConnections[string(key)]; ok {
				override := overrideStatsForConnection(*prev, now)
				// Entry is already here, add the old connection to override connections
				if existing, ok := client.overrideConnections[string(key)]; ok {
					// If we already have an override, aggregate the two overrides
					override = combineOverrides(override, existing, now)
				}
				client.overrideConnections[string(key)] = override
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
			newOverride := overrideStatsForConnection(*prev, now)
			if override, ok := client.overrideConnections[string(key)]; ok {
				// If we already have an override aggregate the two overrides
				newOverride = combineOverrides(override, newOverride, now)
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
			aggregateConnWithOverride(&c, &override)
			delete(client.overrideConnections, key)
		}

		if stats, ok := client.stats[key]; ok {
			// TODO: Or is the underflow here?
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
		stats:               map[string]*stats{},
		closedConnections:   map[string]*ConnectionStats{},
		overrideConnections: map[string]overrideStats{},
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
		st, ok := client.stats[key]
		if !ok {
			st = &stats{}
			client.stats[key] = st
		}

		// If we have an override for this conn for this client, aggregate the conn
		if override, ok := client.overrideConnections[key]; ok {
			aggregateConnWithOverride(conn, &override)
			// TODO: Should we delete from overrides here?
			// TODO: Why don't we just update stats instead of creating override object
		}

		// TODO: This is likely where the uint64 underflow is happening, stats.totalSent is bigger than the
		//       current connections monotonic counter
		// TODO: Possibly not even set the last* counters here
		conn.LastSentBytes = conn.MonotonicSentBytes - st.totalSent
		conn.LastRecvBytes = conn.MonotonicRecvBytes - st.totalRecv
		conn.LastRetransmits = conn.MonotonicRetransmits - st.totalRetransmits

		st.totalSent = conn.MonotonicSentBytes
		st.totalRecv = conn.MonotonicRecvBytes
		st.totalRetransmits = conn.MonotonicRetransmits

		st.lastUpdate = now
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
func aggregateConnWithOverride(cs *ConnectionStats, overrideStats *overrideStats) {
	cs.LastSentBytes += overrideStats.lastSent
	cs.MonotonicSentBytes += overrideStats.totalSent
	cs.LastRecvBytes += overrideStats.lastRecv
	cs.MonotonicRecvBytes += overrideStats.totalRecv
	cs.LastRetransmits += overrideStats.lastRetransmits
	cs.MonotonicRetransmits += overrideStats.totalRetransmits
}

// combineOverrides returns an aggregation of two stats
func combineOverrides(s1, s2 overrideStats, now time.Time) overrideStats {
	return overrideStats{
		lastSent:         s1.lastSent + s2.lastSent,
		lastRecv:         s1.lastRecv + s2.lastRecv,
		lastRetransmits:  s1.lastRetransmits + s2.lastRetransmits,
		totalSent:        s1.totalSent + s2.totalSent,
		totalRecv:        s1.totalRecv + s2.totalRecv,
		totalRetransmits: s1.totalRetransmits + s2.totalRetransmits,
		lastUpdate:       now,
	}
}

func overrideStatsForConnection(conn ConnectionStats, now time.Time) overrideStats {
	return overrideStats{
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
	// Add all closed connections to `latest` map, overwriting existing entries on conflict
	for _, c := range closed {
		key, err := c.ByteKey(ns.buf)
		if err != nil {
			log.Warn("failed to create byte key: %s", err)
			continue
		}
		latest[string(key)] = &c
	}

	connections := make([]ConnectionStats, 0, len(latest))
	for _, c := range latest {
		connections = append(connections, *c)
	}
	return connections
}

// GetStats returns a map of statistics about the current network state
func (ns *networkState) GetStats() map[string]interface{} {
	ns.Lock()
	defer ns.Unlock()

	clientInfo := map[string]interface{}{}
	for id, c := range ns.clients {
		clientInfo[id] = map[string]int{
			"stats":              len(c.stats),
			"override_stats":     len(c.overrideConnections),
			"closed_connections": len(c.closedConnections),
			"last_fetch":         int(c.lastFetch.Unix()),
		}
	}

	return map[string]interface{}{
		"clients":      clientInfo,
		"current_time": time.Now(),
	}
}
