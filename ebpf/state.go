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
	// With clients checking connection stats roughly every 30s, this gives us roughly ~1.6k + ~2.5k objects a second respectively.
	defaultMaxClosedConns = 50000 // ~100 bytes per conn = 5MB
	defaultMaxClientStats = 75000
	defaultExpiry         = 2 * time.Minute
	defaultClientInterval = 30 * time.Second
)

// NetworkState takes care of handling the logic for:
// - closed connections
// - sent and received bytes per connection
type NetworkState interface {
	// Connections returns the list of connections for the given client when provided the latest set of active connections
	Connections(clientID string, latestTime uint64, latestConns []ConnectionStats) []ConnectionStats

	// StoreClosedConnection stores a new closed connection
	StoreClosedConnection(conn ConnectionStats)

	// RemoveClient stops tracking stateful data for a given client
	RemoveClient(clientID string)

	// GetStats returns a map of statistics about the current network state
	GetStats(closedPollLost, closedPollReceived, tracerSkippedCount uint64) map[string]interface{}
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

	lastUpdateEpoch uint64
}

type client struct {
	lastFetch time.Time

	closedConnections map[string]ConnectionStats
	stats             map[string]*stats
}

type networkState struct {
	sync.Mutex

	clients   map[string]*client
	telemetry telemetry

	buf             *bytes.Buffer // Shared buffer
	latestTimeEpoch uint64

	// Network state configuration
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
func (ns *networkState) Connections(id string, latestTime uint64, latestConns []ConnectionStats) []ConnectionStats {
	ns.Lock()
	defer ns.Unlock()

	// Update the latest known time
	ns.latestTimeEpoch = latestTime

	// If its the first time we've seen this client, use global state as connection set
	if ok := ns.newClient(id); !ok {
		return latestConns
	}

	// Update all connections with relevant up-to-date stats for client
	conns := ns.mergeConnections(id, getConnsByKey(latestConns, ns.buf))

	// Flush closed connection map
	ns.clients[id].closedConnections = map[string]ConnectionStats{}

	return conns
}

// getConnsByKey returns a mapping of byte-key -> connection for easier access + manipulation
func getConnsByKey(conns []ConnectionStats, buf *bytes.Buffer) map[string]*ConnectionStats {
	connsByKey := make(map[string]*ConnectionStats, len(conns))
	for i, c := range conns {
		key, err := c.ByteKey(buf)
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
	log.Warnf("closed connection: %v", conn)
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

// mergeConnections return the connections and takes care of updating their last stat counters
func (ns *networkState) mergeConnections(id string, active map[string]*ConnectionStats) []ConnectionStats {
	now := time.Now()

	client := ns.clients[id]
	client.lastFetch = now

	conns := make([]ConnectionStats, 0)

	// Active connections
	for key, c := range active {
		if _, ok := client.stats[key]; !ok {
			if len(client.stats) >= ns.maxClientStats {
				ns.telemetry.connDropped++
				continue
			}
			client.stats[key] = &stats{}
		}

		ns.updateConnWithStats(client, key, c, now)

		conns = append(conns, *c)
	}

	return conns
}

func (ns *networkState) updateConnWithStats(client *client, key string, c *ConnectionStats, now time.Time) {
	if st, ok := client.stats[key]; ok {
		// Check for underflow
		if c.MonotonicSentBytes < st.totalSent || c.MonotonicRecvBytes < st.totalRecv || c.MonotonicRetransmits < st.totalRetransmits {
			log.Warnf("Underflow occured ! stats: %+v, conn: %v: %v", *st, *c)
			ns.telemetry.underflows++
		} else {
			c.LastSentBytes = c.MonotonicSentBytes - st.totalSent
			c.LastRecvBytes = c.MonotonicRecvBytes - st.totalRecv
			c.LastRetransmits = c.MonotonicRetransmits - st.totalRetransmits
		}

		// Update stats object with latest values
		st.totalSent = c.MonotonicSentBytes
		st.totalRecv = c.MonotonicRecvBytes
		st.totalRetransmits = c.MonotonicRetransmits
		st.lastUpdateEpoch = c.LastUpdateEpoch
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
}

func (ns *networkState) removeExpiredStats(c *client, latestTimeEpoch uint64) int {
	return 0
}

// GetStats returns a map of statistics about the current network state
func (ns *networkState) GetStats(closedPollLost, closedPollReceived, tracerSkipped uint64) map[string]interface{} {
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
			"closed_conn_polling_lost":     int(closedPollLost),
			"closed_conn_polling_received": int(closedPollReceived),
			"tracer_conns_skipped":         int(tracerSkipped), // Skipped connections (e.g. Local DNS requests)
		},
		"current_time":       time.Now().Unix(),
		"latest_bpf_time_ns": ns.latestTimeEpoch,
		"test":               1,
	}
}
