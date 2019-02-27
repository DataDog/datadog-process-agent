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
	DEBUGCLIENT = "-1"

	// defaultMaxClosedConns & defaultMaxClientStats are the maximum number of objects that can be stored in-memory.
	// With clients checking connection stats roughly every 30s, this gives us roughly 2500 + 5000 objects a second respectively.
	defaultMaxClosedConns = 75000 // ~100 bytes per conn = 7.5MB
	defaultMaxClientStats = 150000
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

	// GetStats returns a map of statistics about the current network state
	GetStats(closedPollingLost, closedPollingReceived uint64) map[string]interface{}
}

type telemetry struct {
	unorderedConns    int
	closedConnDropped int
	connDropped       int
	underflows        int
}

type stats struct {
	totalSent        uint64
	totalRecv        uint64
	totalRetransmits uint32

	lastUpdate time.Time
}

type client struct {
	lastFetch time.Time

	closedConnections map[string]ConnectionStats
	stats             map[string]*stats
}

type networkState struct {
	sync.Mutex
	buf *bytes.Buffer // Shared buffer

	clients   map[string]*client
	telemetry telemetry

	clientInterval time.Duration
	expiry         time.Duration
	maxClosedConns int
	maxClientStats int
}

// NewDefaultNetworkState creates a new network state with default settings
func NewDefaultNetworkState() NetworkState {
	return NewNetworkState(defaultClientInterval, defaultExpiry, defaultMaxClosedConns, defaultMaxClientStats)
}

// NewNetworkState creates a new network state
func NewNetworkState(clientInterval, expiry time.Duration, maxClosedConns, maxClientStats int) NetworkState {
	ns := &networkState{
		clients:        map[string]*client{},
		telemetry:      telemetry{},
		clientInterval: clientInterval,
		expiry:         expiry,
		maxClosedConns: maxClosedConns,
		maxClientStats: maxClientStats,
		buf:            &bytes.Buffer{},
	}

	go func() {
		count := uint64(0)
		for now := range time.NewTicker(ns.clientInterval).C {
			count++
			// Every 10 ticks, lets check for any outdated stats objects to remove & flush telemetry
			clearExpiredStats, flushTelemetry := count%10 == 0, count%10 == 0
			ns.cleanupState(now, clearExpiredStats, flushTelemetry)
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
				ns.telemetry.unorderedConns++
				continue
			}

			conn.MonotonicSentBytes += prev.MonotonicSentBytes
			conn.MonotonicRecvBytes += prev.MonotonicRecvBytes
			conn.MonotonicRetransmits += prev.MonotonicRetransmits
		} else if len(client.closedConnections) >= ns.maxClosedConns {
			ns.telemetry.closedConnDropped++
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

// getConnections return the connections and takes care of updating their last stat counters
func (ns *networkState) getConnections(id string, active map[string]*ConnectionStats) []ConnectionStats {
	now := time.Now()

	client := ns.clients[id]
	client.lastFetch = now

	conns := make([]ConnectionStats, 0)

	// Closed connections
	for key, c := range client.closedConnections {
		if c2, ok := active[key]; ok { // This closed connection has become active again
			// If we're seeing unexpected ordering, lets not combine these two connections.
			if c.LastUpdateEpoch >= c2.LastUpdateEpoch {
				ns.telemetry.unorderedConns++
				// TODO: Should we `continue`?
			} else {
				c.MonotonicSentBytes += c2.MonotonicSentBytes
				c.MonotonicRecvBytes += c2.MonotonicRecvBytes
				c.MonotonicRetransmits += c2.MonotonicRetransmits
			}

			if _, ok := client.stats[key]; !ok {
				if len(client.stats) >= ns.maxClientStats {
					ns.telemetry.connDropped++
					continue
				}
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
			// If this connection was both closed and reopened, update the counters to reflect only the active connection.
			// The monotonic counters will be the sum of all connections that cross our interval start + finish.
			if stats, ok := client.stats[key]; ok {
				stats.totalRetransmits = c.MonotonicRetransmits
				stats.totalSent = c.MonotonicSentBytes
				stats.totalRecv = c.MonotonicRecvBytes
			}
			continue // We processed this connection during the closed connection pass, so lets not do it again.
		}

		if _, ok := client.stats[key]; !ok {
			if len(client.stats) >= ns.maxClientStats {
				ns.telemetry.connDropped++
				continue
			}
			client.stats[key] = &stats{}
		}

		ns.updateConnWithStats(client, key, c, false, now)

		conns = append(conns, *c)
	}

	return conns
}

func (ns *networkState) updateConnWithStats(client *client, key string, c *ConnectionStats, shouldRemoveStats bool, now time.Time) {
	if st, ok := client.stats[key]; ok {
		// Check for underflow
		if c.MonotonicSentBytes < st.totalSent || c.MonotonicRecvBytes < st.totalRecv || c.MonotonicRetransmits < st.totalRetransmits {
			ns.telemetry.underflows++
		} else {
			c.LastSentBytes = c.MonotonicSentBytes - st.totalSent
			c.LastRecvBytes = c.MonotonicRecvBytes - st.totalRecv
			c.LastRetransmits = c.MonotonicRetransmits - st.totalRetransmits
		}

		if shouldRemoveStats {
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

func (ns *networkState) cleanupState(now time.Time, clearExpiredStats, flushStats bool) {
	ns.Lock()
	defer ns.Unlock()

	// Remove expired clients + stats
	deletedStats := 0
	for id, c := range ns.clients {
		if c.lastFetch.Add(ns.expiry).Before(now) {
			delete(ns.clients, id)
		} else if clearExpiredStats { // Look for inactive stats objects and remove them
			deletedStats += ns.removeExpiredStats(c, now)
		}
	}

	if deletedStats > 0 {
		log.Debugf("removed %d expired stats objects in %d", deletedStats, time.Now().Sub(now))
	}

	if flushStats {
		// Only flush log line if any metric is non-zero
		if ns.telemetry.unorderedConns > 0 || ns.telemetry.underflows > 0 || ns.telemetry.closedConnDropped > 0 || ns.telemetry.connDropped > 0 {
			log.Debugf("state telemetry: [%d unordered conns] [%d stats underflows] [%d connections dropped due to stats] [%d closed connections dropped]",
				ns.telemetry.unorderedConns,
				ns.telemetry.underflows,
				ns.telemetry.closedConnDropped,
				ns.telemetry.connDropped)
		}
		ns.telemetry = telemetry{} // Reset counters
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
func (ns *networkState) GetStats(closedPollingLost, closedPollingReceived uint64) map[string]interface{} {
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
		"clients": clientInfo,
		"telemetry": map[string]int{
			"underflows":                   ns.telemetry.underflows,
			"unordered_conns":              ns.telemetry.unorderedConns,
			"closed_conn_dropped":          ns.telemetry.closedConnDropped,
			"conn_dropped":                 ns.telemetry.connDropped,
			"closed_conn_polling_lost":     int(closedPollingLost),
			"closed_conn_polling_received": int(closedPollingReceived),
		},
		"current_time": time.Now(),
	}
}
