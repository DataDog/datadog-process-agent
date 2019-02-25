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
	maxClientClosedConns  = 150000 // 5000 connections closing a second
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

	// GetStats returns a map of statistics about the current network state
	GetStats() map[string]interface{}
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
	closedConnections map[string]ConnectionStats
	stats             map[string]*stats
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

	// If its the first time we've seen this client, use global state as connection set
	if ok := ns.newClient(id); !ok {
		return latestConns
	}

	// Update all connections with relevant up-to-date stats for client
	conns := ns.getConnections(id, ns.getConnsByKey(latestConns))

	// Flush closed connection map
	ns.clients[id].closedConnections = map[string]ConnectionStats{}

	return conns
}

// getConnsByKey returns a mapping of byte-key -> connection for easier access + manipulation
func (ns *networkState) getConnsByKey(conns []ConnectionStats) map[string]*ConnectionStats {
	connsByKey := make(map[string]*ConnectionStats, len(conns))
	for i, c := range conns {
		key, err := c.ByteKey(ns.buf)
		if err != nil {
			log.Warn("failed to create byte key: %s", err)
			continue
		}
		connsByKey[string(key)] = &conns[i]
	}
	return connsByKey
}

// StoreClosedConnection stores the given connection for every client
func (ns *networkState) StoreClosedConnection(conn ConnectionStats) {
	ns.Lock()
	defer ns.Unlock()

	key, err := conn.ByteKey(ns.buf)
	if err != nil {
		log.Warn("failed to create byte key: %s", err)
		return
	}

	for _, client := range ns.clients {
		// If we've seen this closed connection already, lets combine the two
		if prev, ok := client.closedConnections[string(key)]; ok {
			// We received either the connections either out of order, or it's the same one we've already seen.
			// Lets skip it for now.
			if prev.LastUpdateEpoch >= conn.LastUpdateEpoch {
				// TODO: Add log and/or metric for this, so we can see how often it happens
				continue
			}

			conn.MonotonicSentBytes += prev.MonotonicSentBytes
			conn.MonotonicRecvBytes += prev.MonotonicRecvBytes
			conn.MonotonicRetransmits += prev.MonotonicRetransmits
		} else if len(client.closedConnections) >= maxClientClosedConns {
			// TODO: Add log and/or metric for this, so we can see how often it happens
			continue
		}

		client.closedConnections[string(key)] = conn
	}
}

// newClient creates a new client and returns true if the given client already exists
func (ns *networkState) newClient(clientID string) bool {
	if _, ok := ns.clients[clientID]; ok {
		return true
	}

	ns.clients[clientID] = &client{
		lastFetch:         time.Now(),
		stats:             map[string]*stats{},
		closedConnections: map[string]ConnectionStats{},
	}
	return false
}

// getConnections return the connections and takes care of updating their last stats
func (ns *networkState) getConnections(id string, active map[string]*ConnectionStats) []ConnectionStats {
	now := time.Now()

	client := ns.clients[id]
	client.lastFetch = now

	conns := make([]ConnectionStats, 0)

	// Closed connections
	for key, c := range client.closedConnections {
		if c2, ok := active[key]; ok { // This closed connection has become active again
			if c.LastUpdateEpoch >= c2.LastUpdateEpoch {
				// We're seeing unexpected ordering. Lets not combine these two connections
				// TODO: Add logging/metrics
			} else {
				c.MonotonicSentBytes += c2.MonotonicSentBytes
				c.MonotonicRecvBytes += c2.MonotonicRecvBytes
				c.MonotonicRetransmits += c2.MonotonicRetransmits
			}

			if _, ok := client.stats[key]; !ok {
				client.stats[key] = &stats{}
			}

			ns.updateConnWithStats(client, key, &c, false, now)
		} else { // Since connection is no longer active, lets just remove the stats object
			ns.updateConnWithStats(client, key, &c, true, now)
		}

		conns = append(conns, c)
	}

	// Active connections
	for key, c := range active {
		if _, ok := client.closedConnections[key]; ok {
			// TODO: This is hacky - explain why we do it (accurate counting across boundaries. Monotonic counters are wonky though.)
			// Monotonic counters are the sum of all connections that cross our interval start + finish
			if stats, ok := client.stats[key]; ok {
				stats.totalRetransmits = c.MonotonicRetransmits
				stats.totalSent = c.MonotonicSentBytes
				stats.totalRecv = c.MonotonicRecvBytes
			}
			// We already processed this connection above, during the closed connection pass, so lets not do it again
			continue
		}

		if _, ok := client.stats[key]; !ok {
			client.stats[key] = &stats{}
		}

		ns.updateConnWithStats(client, key, c, false, now)

		conns = append(conns, *c)
	}

	return conns
}

func (ns *networkState) updateConnWithStats(client *client, key string, c *ConnectionStats, removeStats bool, now time.Time) {
	if st, ok := client.stats[key]; ok {
		// TODO: This is likely where the uint64 underflow is happening, stats.totalSent is bigger than the
		//       current connections monotonic counter
		c.LastSentBytes = c.MonotonicSentBytes - st.totalSent
		c.LastRecvBytes = c.MonotonicRecvBytes - st.totalRecv
		c.LastRetransmits = c.MonotonicRetransmits - st.totalRetransmits

		if removeStats {
			delete(client.stats, key)
		} else {
			st.totalSent = c.MonotonicSentBytes
			st.totalRecv = c.MonotonicRecvBytes
			st.totalRetransmits = c.MonotonicRetransmits
			st.lastUpdate = now
		}
	} else {
		c.LastSentBytes = c.MonotonicSentBytes
		c.LastRecvBytes = c.MonotonicRecvBytes
		c.LastRetransmits = c.MonotonicRetransmits
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
	expired := make([]string, 0)

	for key, s := range c.stats {
		if s.lastUpdate.Add(ns.expiry).Before(now) {
			expired = append(expired, key)
		}
	}

	for _, key := range expired {
		delete(c.stats, key)
	}

	return len(expired)
}

// GetStats returns a map of statistics about the current network state
func (ns *networkState) GetStats() map[string]interface{} {
	ns.Lock()
	defer ns.Unlock()

	clientInfo := map[string]interface{}{}
	for id, c := range ns.clients {
		clientInfo[id] = map[string]int{
			"stats":              len(c.stats),
			"closed_connections": len(c.closedConnections),
			"last_fetch":         int(c.lastFetch.Unix()),
		}
	}

	return map[string]interface{}{
		"clients":      clientInfo,
		"current_time": time.Now(),
	}
}
