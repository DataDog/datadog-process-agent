package ebpf

import (
	"bytes"
	"sort"
	"strings"
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

// mergeConnections return the connections and takes care of updating their last stat counters
func (ns *networkState) mergeConnections(id string, active map[string]*ConnectionStats) []ConnectionStats {
	now := time.Now()

	client := ns.clients[id]
	client.lastFetch = now

	conns := make([]ConnectionStats, 0)

	// Closed connections
	for key, closedConn := range client.closedConnections {
		if activeConn, ok := active[key]; ok { // This closed connection has become active again
			// If we're seeing unexpected ordering, lets not combine these two connections.
			if closedConn.LastUpdateEpoch >= activeConn.LastUpdateEpoch {
				ns.telemetry.unorderedConns++
				// TODO: Should we `continue`?
			} else {
				closedConn.MonotonicSentBytes += activeConn.MonotonicSentBytes
				closedConn.MonotonicRecvBytes += activeConn.MonotonicRecvBytes
				closedConn.MonotonicRetransmits += activeConn.MonotonicRetransmits
			}

			if _, ok := client.stats[key]; !ok {
				if len(client.stats) >= ns.maxClientStats {
					ns.telemetry.connDropped++
					continue
				}
				client.stats[key] = &stats{}
			}

			ns.updateConnWithStats(client, key, &closedConn, now)
		} else {
			ns.updateConnWithStats(client, key, &closedConn, now)
			// Since connection is no longer active, lets just remove the stats object afterwords
			if _, ok := client.stats[key]; ok {
				delete(client.stats, key)
			}
		}

		conns = append(conns, closedConn)
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

		ns.updateConnWithStats(client, key, c, now)

		conns = append(conns, *c)
	}

	return conns
}

func commonPorts(m map[uint16]int) map[uint16]struct{} {
	ports := make(map[uint16]struct{})
	for p, count := range m {
		if count > 100 { // TODO: Make configurable
			ports[p] = struct{}{}
		}
	}
	return ports
}

func aggregateConnections(conns []ConnectionStats) []ConnectionStats {
	aggrConns := make([]ConnectionStats, 0)

	sort.Slice(conns, func(i, j int) bool {
		if conns[i].Pid < conns[j].Pid { // Sort first by PID
			return true
		} else if conns[i].Pid == conns[j].Pid { // Then by destination IP
			if comp := strings.Compare(conns[i].Dest, conns[j].Dest); comp == -1 {
				return true
			} else if comp == 0 { // Then by source IP
				return strings.Compare(conns[i].Source, conns[j].Source) == -1
			}
		}
		return false
	})

	// Go over PID sub-ranges
	applyFuncOnRange(conns,
		func(a, b *ConnectionStats) bool {
			return a.Pid == b.Pid
		},
		func(pidRange []ConnectionStats) {
			// Find common ports for this PID range
			staticSource, staticDest := map[uint16]int{}, map[uint16]int{}
			for _, c := range pidRange {
				staticDest[c.DPort]++
				staticSource[c.SPort]++
			}
			commonSource, commonDest := commonPorts(staticSource), commonPorts(staticDest)

			// Go over IP sub-ranges and aggregate
			applyFuncOnRange(pidRange,
				func(a, b *ConnectionStats) bool {
					return a.Source == b.Source && a.Dest == b.Dest
				},
				func(ipRange []ConnectionStats) {
					aggrConns = append(aggrConns, aggIPRange(ipRange, commonSource, commonDest)...)
				},
			)
		},
	)

	return aggrConns
}

func aggIPRange(conns []ConnectionStats, staticSources, staticDests map[uint16]struct{}) []ConnectionStats {
	source, dest := map[uint16]int{}, map[uint16]int{}
	aggrConns := make([]ConnectionStats, 0)

	for _, c := range conns {
		if _, ok := staticSources[c.SPort]; ok {
			if idx, ok := source[c.SPort]; ok {
				aggregate(aggrConns, idx, c)
			} else {
				c.DPort = 0
				c.RollUpCount++
				aggrConns = append(aggrConns, c)
				source[c.SPort] = len(aggrConns) - 1
			}
		} else if _, ok := staticDests[c.DPort]; ok {
			if idx, ok := dest[c.DPort]; ok {
				aggregate(aggrConns, idx, c)
			} else {
				c.SPort = 0
				c.RollUpCount++
				aggrConns = append(aggrConns, c)
				dest[c.DPort] = len(aggrConns) - 1
			}
		} else {
			aggrConns = append(aggrConns, c)
		}
	}

	return aggrConns
}

func aggregate(aggrConns []ConnectionStats, idx int, c ConnectionStats) {
	aggrConns[idx].LastSentBytes += c.LastSentBytes
	aggrConns[idx].LastRecvBytes += c.LastRecvBytes
	aggrConns[idx].LastRetransmits += c.LastRetransmits
	aggrConns[idx].MonotonicSentBytes += c.MonotonicSentBytes
	aggrConns[idx].MonotonicRecvBytes += c.MonotonicRecvBytes
	aggrConns[idx].MonotonicRetransmits += c.MonotonicRetransmits
	aggrConns[idx].RollUpCount++
}

func (ns *networkState) updateConnWithStats(client *client, key string, c *ConnectionStats, now time.Time) {
	if st, ok := client.stats[key]; ok {
		// Check for underflow
		if c.MonotonicSentBytes < st.totalSent || c.MonotonicRecvBytes < st.totalRecv || c.MonotonicRetransmits < st.totalRetransmits {
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
	ns.Lock()
	defer ns.Unlock()

	// Remove expired clients + stats
	deletedStats := 0
	for id, c := range ns.clients {
		if c.lastFetch.Add(ns.expiry).Before(now) {
			delete(ns.clients, id)
		} else if clearExpiredStats { // Look for inactive stats objects and remove them
			deletedStats += ns.removeExpiredStats(c, ns.latestTimeEpoch)
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

func (ns *networkState) removeExpiredStats(c *client, latestTimeEpoch uint64) int {
	expired := make([]string, 0)
	for key, s := range c.stats {
		if latestTimeEpoch-s.lastUpdateEpoch > uint64(ns.expiry.Nanoseconds()) {
			expired = append(expired, key)
		}
	}

	for _, key := range expired {
		delete(c.stats, key)
	}
	return len(expired)
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
	}
}
