package ebpf

import (
	"fmt"
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
	RemoveClient(clientID string) error
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
	closedConnections []*ConnectionStats
	stats             map[string]*sendRecvStats
}

type networkState struct {
	clients      map[string]*client
	clientsMutex sync.Mutex

	connections []ConnectionStats
	connsMutex  sync.Mutex

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
		connections:   []ConnectionStats{},
		cleanInterval: cleanInterval,
		clientExpiry:  clientExpiry,
	}

	// Start tracking expiry time for clients
	go func() {
		for now := range time.NewTicker(ns.cleanInterval).C {
			ns.trackClientExpiry(now)
		}
	}()

	return ns
}

func (ns *networkState) getClients() []string {
	ns.clientsMutex.Lock()
	defer ns.clientsMutex.Unlock()
	clients := make([]string, 0, len(ns.clients))

	for id := range ns.clients {
		clients = append(clients, id)
	}

	return clients
}

func (ns *networkState) Connections(id string) []ConnectionStats {
	ns.connsMutex.Lock()
	defer ns.connsMutex.Unlock()

	if old := ns.newClient(id); !old {
		// First time we see this client, use global state
		return ns.connections
	}

	conns := removeDuplicates(append(ns.closedConns(id), ns.connections...))

	// Update send/recv bytes stats
	ns.clientsMutex.Lock()
	defer ns.clientsMutex.Unlock()
	for i, conn := range conns {
		key, err := conn.StrKey()
		if err != nil {
			log.Errorf("could not get string key for conn: %v: %s", conn, err)
			continue
		}

		if _, ok := ns.clients[id].stats[key]; !ok {
			ns.clients[id].stats[key] = &sendRecvStats{}
		}

		prev := ns.clients[id].stats[key]
		ns.clients[id].stats[key].lastSent = conn.MonotonicSentBytes - prev.totalSent
		ns.clients[id].stats[key].lastRecv = conn.MonotonicRecvBytes - prev.totalRecv
		ns.clients[id].stats[key].lastRetransmits = conn.MonotonicRetransmits - prev.totalRetransmits
		ns.clients[id].stats[key].totalSent = conn.MonotonicSentBytes
		ns.clients[id].stats[key].totalRecv = conn.MonotonicRecvBytes
		ns.clients[id].stats[key].totalRetransmits = conn.MonotonicRetransmits

		conns[i].LastSentBytes = prev.lastSent
		conns[i].LastRecvBytes = prev.lastRecv
		conns[i].LastRetransmits = prev.lastRetransmits
	}

	return conns
}

func (ns *networkState) StoreConnections(conns []ConnectionStats) {
	// Update connections
	ns.connsMutex.Lock()
	defer ns.connsMutex.Unlock()
	ns.connections = conns
}

// StoreClosedConnection stores the given connection for every client
func (ns *networkState) StoreClosedConnection(conn ConnectionStats) {
	ns.clientsMutex.Lock()
	defer ns.clientsMutex.Unlock()

	for id := range ns.clients {
		// TODO clear the stats entry for this connection
		// We only store the pointer to the connection, when it will be cleared for each client it will get GCed
		ns.clients[id].closedConnections = append(ns.clients[id].closedConnections, &conn)
	}
}

// closedConns returns the closed connections for the given client and takes care of updating last fetch
// the provided client is supposed to exist
func (ns *networkState) closedConns(clientID string) []ConnectionStats {
	conns := []ConnectionStats{}

	ns.clientsMutex.Lock()
	defer ns.clientsMutex.Unlock()

	for _, conn := range ns.clients[clientID].closedConnections {
		conns = append(conns, *conn)
	}

	// Flush closed connections for this client
	ns.clients[clientID].closedConnections = []*ConnectionStats{}
	ns.clients[clientID].lastFetch = time.Now()
	return conns
}

// newClient creates a new client and returns true if the given client already exists
func (ns *networkState) newClient(clientID string) bool {
	ns.clientsMutex.Lock()
	defer ns.clientsMutex.Unlock()
	if _, ok := ns.clients[clientID]; ok {
		return true
	}

	ns.clients[clientID] = &client{
		lastFetch: time.Now(),
		stats:     map[string]*sendRecvStats{},
	}
	return false
}

func (ns *networkState) RemoveClient(clientID string) error {
	ns.clientsMutex.Lock()
	defer ns.clientsMutex.Unlock()

	if _, ok := ns.clients[clientID]; !ok {
		return fmt.Errorf("can't remove client %s, it is not stored", clientID)
	}

	delete(ns.clients, clientID)
	return nil
}

func (ns *networkState) trackClientExpiry(now time.Time) {
	ns.clientsMutex.Lock()
	defer ns.clientsMutex.Unlock()
	for id, c := range ns.clients {
		if c.lastFetch.Add(ns.clientExpiry).Before(now) {
			delete(ns.clients, id)
		}
	}
}
