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
	Connections(clientID string) []ConnectionStats
	StoreConnections(conns []ConnectionStats)
	StoreClosedConnection(conn ConnectionStats)
	RemoveClient(clientID string)
	getClients() []string
}

type sendRecvStats struct {
	totalSent uint64
	lastSent  uint64

	totalRecv uint64
	lastRecv  uint64

	totalRetransmits uint32
	lastRetransmits  uint32
}

type client struct {
	lastFetch         time.Time
	closedConnections map[string]*ConnectionStats
	stats             map[string]*sendRecvStats
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

	// TODO check for duplicates here
	return append(ns.closedConns(id), ns.getConnections(id)...)
}

func (ns *networkState) StoreConnections(conns []ConnectionStats) {
	// Update connections
	ns.Lock()
	defer ns.Unlock()

	buf := &bytes.Buffer{}
	for _, c := range conns {
		rawKey, err := c.ByteKey(buf)
		if err != nil {
			log.Errorf("%s", err)
			continue
		}

		// copy to get pointer to struct
		c2 := c
		// TODO aggregate
		ns.connections[string(rawKey)] = &c2
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
		// TODO clear the stats entry for this connection
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

	for _, conn := range ns.clients[clientID].closedConnections {
		conns = append(conns, *conn)
	}

	// Flush closed connections for this client
	ns.clients[clientID].closedConnections = map[string]*ConnectionStats{}
	ns.clients[clientID].lastFetch = time.Now()
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
		lastFetch:         time.Now(),
		stats:             map[string]*sendRecvStats{},
		closedConnections: map[string]*ConnectionStats{},
	}
	return false
}

// getConnections return the connections and takes care of updating their last stats
func (ns *networkState) getConnections(id string) []ConnectionStats {
	ns.Lock()
	defer ns.Unlock()

	conns := make([]ConnectionStats, 0, len(ns.connections))

	// Update send/recv bytes stats
	for key, conn := range ns.connections {
		if _, old := ns.clients[id].stats[key]; !old {
			ns.clients[id].stats[key] = &sendRecvStats{}
		}

		prev := ns.clients[id].stats[key]
		ns.clients[id].stats[key].lastSent = conn.MonotonicSentBytes - prev.totalSent
		ns.clients[id].stats[key].lastRecv = conn.MonotonicRecvBytes - prev.totalRecv
		ns.clients[id].stats[key].lastRetransmits = conn.MonotonicRetransmits - prev.totalRetransmits

		conn.LastSentBytes = prev.lastSent
		conn.LastRecvBytes = prev.lastRecv
		conn.LastRetransmits = prev.lastRetransmits

		ns.clients[id].stats[key].totalSent = conn.MonotonicSentBytes
		ns.clients[id].stats[key].totalRecv = conn.MonotonicRecvBytes
		ns.clients[id].stats[key].totalRetransmits = conn.MonotonicRetransmits

		conns = append(conns, *conn)
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
