// +build linux_bpf

package ebpf

import (
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRetrieveClosedConnection(t *testing.T) {
	conn := ConnectionStats{
		Pid:                  123,
		Type:                 TCP,
		Family:               AFINET,
		Source:               "localhost",
		Dest:                 "localhost",
		SPort:                31890,
		DPort:                80,
		MonotonicSentBytes:   12345,
		LastSentBytes:        12345,
		MonotonicRecvBytes:   6789,
		LastRecvBytes:        6789,
		MonotonicRetransmits: 2,
		LastRetransmits:      2,
	}

	clientID := 1

	t.Run("without prior registration", func(t *testing.T) {
		state := NewDefaultNetworkState()
		state.StoreClosedConnection(conn)
		conns := state.Connections(clientID)

		assert.Equal(t, 0, len(conns))
	})

	t.Run("with registration", func(t *testing.T) {
		state := NewDefaultNetworkState()

		conns := state.Connections(clientID)
		assert.Equal(t, 0, len(conns))

		state.StoreClosedConnection(conn)

		conns = state.Connections(clientID)
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, conn, conns[0])

		// An other client that is not registered should not have the closed connection
		conns = state.Connections(clientID + 1)
		assert.Equal(t, 0, len(conns))

		// It should no more have connections stored
		conns = state.Connections(clientID)
		assert.Equal(t, 0, len(conns))
	})
}

func TestCleanupClient(t *testing.T) {
	clientID := 1

	wait := 100 * time.Millisecond

	state := NewNetworkState(defaultCleanInterval, wait)
	clients := state.Clients()
	assert.Equal(t, 0, len(clients))

	conns := state.Connections(clientID)
	assert.Equal(t, 0, len(conns))

	// Should be a no op
	state.(*networkState).trackClientExpiry(time.Now())

	clients = state.Clients()
	assert.Equal(t, 1, len(clients))
	assert.Equal(t, 1, clients[0])

	time.Sleep(wait)

	// Should delete the client 1
	state.(*networkState).trackClientExpiry(time.Now())

	clients = state.Clients()
	assert.Equal(t, 0, len(clients))
}

func TestLastStats(t *testing.T) {
	client1 := 1
	client2 := 2
	state := NewDefaultNetworkState()

	dSent := uint64(42)
	dRecv := uint64(133)
	dRetransmits := uint32(7)

	conn := ConnectionStats{
		Pid:                  123,
		Type:                 TCP,
		Family:               AFINET,
		Source:               "localhost",
		Dest:                 "localhost",
		SPort:                31890,
		DPort:                80,
		MonotonicSentBytes:   36,
		MonotonicRecvBytes:   24,
		MonotonicRetransmits: 2,
	}

	conn2 := conn
	conn2.MonotonicSentBytes += dSent
	conn2.MonotonicRecvBytes += dRecv
	conn2.MonotonicRetransmits += dRetransmits

	conn3 := conn2
	conn3.MonotonicSentBytes += dSent
	conn3.MonotonicRecvBytes += dRecv
	conn3.MonotonicRetransmits += dRetransmits

	// First get, we should not have any connections stored
	conns := state.Connections(client1)
	assert.Equal(t, 0, len(conns))

	// Same for an other client
	conns = state.Connections(client2)
	assert.Equal(t, 0, len(conns))

	state.StoreConnections([]ConnectionStats{conn})

	// We should have only one connection but without last stats (= 0)
	conns = state.Connections(client1)
	assert.Equal(t, 1, len(conns))
	assert.Equal(t, conn.MonotonicSentBytes, conns[0].LastSentBytes)
	assert.Equal(t, conn.MonotonicRecvBytes, conns[0].LastRecvBytes)
	assert.Equal(t, conn.MonotonicRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn.MonotonicRetransmits, conns[0].MonotonicRetransmits)

	state.StoreConnections([]ConnectionStats{conn2})

	// This client didn't collected the first connection so
	// we should have last stats = to monotonic stats
	conns = state.Connections(client2)
	assert.Equal(t, 1, len(conns))
	assert.Equal(t, conn2.MonotonicSentBytes, conns[0].LastSentBytes)
	assert.Equal(t, conn2.MonotonicRecvBytes, conns[0].LastRecvBytes)
	assert.Equal(t, conn2.MonotonicRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn2.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn2.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn2.MonotonicRetransmits, conns[0].MonotonicRetransmits)

	state.StoreConnections([]ConnectionStats{conn3})

	// Client 1 should have conn3 - conn1 since it did not collected conn2
	conns = state.Connections(client1)
	assert.Equal(t, 1, len(conns))
	assert.Equal(t, 2*dSent, conns[0].LastSentBytes)
	assert.Equal(t, 2*dRecv, conns[0].LastRecvBytes)
	assert.Equal(t, 2*dRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn3.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn3.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn3.MonotonicRetransmits, conns[0].MonotonicRetransmits)

	// Client 2 should have conn3 - conn2
	conns = state.Connections(client2)
	assert.Equal(t, 1, len(conns))
	assert.Equal(t, dSent, conns[0].LastSentBytes)
	assert.Equal(t, dRecv, conns[0].LastRecvBytes)
	assert.Equal(t, dRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn3.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn3.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn3.MonotonicRetransmits, conns[0].MonotonicRetransmits)
}

func TestLastStatsForClosedConnection(t *testing.T) {
	clientID := 1
	state := NewDefaultNetworkState()

	dSent := uint64(42)
	dRecv := uint64(133)
	dRetransmits := uint32(0)

	conn := ConnectionStats{
		Pid:                  123,
		Type:                 TCP,
		Family:               AFINET,
		Source:               "localhost",
		Dest:                 "localhost",
		SPort:                31890,
		DPort:                80,
		MonotonicSentBytes:   36,
		MonotonicRecvBytes:   24,
		MonotonicRetransmits: 1,
	}

	conn2 := conn
	conn2.MonotonicSentBytes += dSent
	conn2.MonotonicRecvBytes += dRecv
	conn2.MonotonicRetransmits += dRetransmits

	// First get, we should not have any connections stored
	conns := state.Connections(clientID)
	assert.Equal(t, 0, len(conns))

	// Store the connection
	state.StoreConnections([]ConnectionStats{conn})

	// We should have one connection without last stats
	conns = state.Connections(clientID)
	assert.Equal(t, 1, len(conns))
	assert.Equal(t, conn.MonotonicSentBytes, conns[0].LastSentBytes)
	assert.Equal(t, conn.MonotonicRecvBytes, conns[0].LastRecvBytes)
	assert.Equal(t, conn.MonotonicRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn.MonotonicRetransmits, conns[0].MonotonicRetransmits)

	// Store the connection as closed
	state.StoreClosedConnection(conn2)

	// We should have one connection with last stats
	conns = state.Connections(clientID)
	assert.Equal(t, 1, len(conns))
	assert.Equal(t, dSent, conns[0].LastSentBytes)
	assert.Equal(t, dRecv, conns[0].LastRecvBytes)
	assert.Equal(t, dRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn2.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn2.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn2.MonotonicRetransmits, conns[0].MonotonicRetransmits)
}

func TestRaceConditions(t *testing.T) {
	clients := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	// Generate random conns
	genConns := func(n uint32) []ConnectionStats {
		conns := make([]ConnectionStats, 0, n)
		for i := uint32(0); i < n; i++ {
			conns = append(conns, ConnectionStats{
				Pid:                  1 + i,
				Type:                 TCP,
				Family:               AFINET,
				Source:               "localhost",
				Dest:                 "localhost",
				SPort:                uint16(rand.Int()),
				DPort:                uint16(rand.Int()),
				MonotonicSentBytes:   uint64(rand.Int()),
				MonotonicRecvBytes:   uint64(rand.Int()),
				MonotonicRetransmits: uint32(rand.Int()),
			})
		}
		return conns
	}

	state := NewDefaultNetworkState()
	nConns := uint32(100)

	var wg sync.WaitGroup
	wg.Add(len(clients))

	// Spawn multiple clients to get multiple times
	for _, c := range clients {
		go func(c int) {
			defer wg.Done()
			defer state.RemoveClient(c)
			timer := time.NewTimer(1 * time.Second)
			for {
				select {
				case <-timer.C:
					return
				default:
					state.Connections(c)
				}
			}
		}(c)
	}

	// Spawn a worker to store random connections
	for i := 0; i < 10; i++ {
		state.StoreConnections(genConns(nConns))
	}

	wg.Wait()
}
