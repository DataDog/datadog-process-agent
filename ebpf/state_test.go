// +build linux_bpf

package ebpf

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func BenchmarkStoreClosedConnection(b *testing.B) {
	conns := generateRandConnections(30000)
	for _, bench := range []struct {
		connCount int
	}{
		{
			connCount: 100,
		},
		{
			connCount: 1000,
		},
		{
			connCount: 10000,
		},
		{
			connCount: 30000,
		},
	} {
		b.Run(fmt.Sprintf("StoreClosedConnection-%d", bench.connCount), func(b *testing.B) {
			ns := NewDefaultNetworkState()
			ns.Connections(DEBUGCLIENT, []ConnectionStats{}) // Initial fetch to set up client

			b.ResetTimer()
			b.ReportAllocs()

			for n := 0; n < b.N; n++ {
				for _, c := range conns[:bench.connCount] {
					ns.StoreClosedConnection(c)
				}
			}
		})
	}
}

func BenchmarkConnectionsGet(b *testing.B) {
	conns := generateRandConnections(30000)
	closed := generateRandConnections(30000)

	for _, bench := range []struct {
		connCount   int
		closedCount int
	}{
		{
			connCount:   100,
			closedCount: 0,
		},
		{
			connCount:   100,
			closedCount: 50,
		},
		{
			connCount:   100,
			closedCount: 100,
		},
		{
			connCount:   1000,
			closedCount: 0,
		},
		{
			connCount:   1000,
			closedCount: 500,
		},
		{
			connCount:   1000,
			closedCount: 1000,
		},
		{
			connCount:   10000,
			closedCount: 0,
		},
		{
			connCount:   10000,
			closedCount: 5000,
		},
		{
			connCount:   10000,
			closedCount: 10000,
		},
		{
			connCount:   30000,
			closedCount: 0,
		},
		{
			connCount:   30000,
			closedCount: 15000,
		},
		{
			connCount:   30000,
			closedCount: 30000,
		},
	} {
		b.Run(fmt.Sprintf("ConnectionsGet-%d-%d", bench.connCount, bench.closedCount), func(b *testing.B) {
			ns := NewDefaultNetworkState()

			// Initial fetch to set up client
			ns.Connections(DEBUGCLIENT, []ConnectionStats{})

			for _, c := range closed[:bench.closedCount] {
				ns.StoreClosedConnection(c)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for n := 0; n < b.N; n++ {
				ns.Connections(DEBUGCLIENT, conns[:bench.connCount])
			}
		})
	}
}

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

	clientID := "1"

	t.Run("without prior registration", func(t *testing.T) {
		state := NewDefaultNetworkState()
		state.StoreClosedConnection(conn)
		conns := state.Connections(clientID, []ConnectionStats{})

		assert.Equal(t, 0, len(conns))
	})

	t.Run("with registration", func(t *testing.T) {
		state := NewDefaultNetworkState()

		conns := state.Connections(clientID, []ConnectionStats{})
		assert.Equal(t, 0, len(conns))

		state.StoreClosedConnection(conn)

		conns = state.Connections(clientID, []ConnectionStats{})
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, conn, conns[0])

		// An other client that is not registered should not have the closed connection
		conns = state.Connections("2", []ConnectionStats{})
		assert.Equal(t, 0, len(conns))

		// It should no more have connections stored
		conns = state.Connections(clientID, []ConnectionStats{})
		assert.Equal(t, 0, len(conns))
	})
}

func TestCleanupClient(t *testing.T) {
	clientID := "1"

	wait := 100 * time.Millisecond

	state := NewNetworkState(defaultClientInterval, wait, defaultMaxClosedConns, defaultMaxClientStats)
	clients := state.(*networkState).getClients()
	assert.Equal(t, 0, len(clients))

	conns := state.Connections(clientID, []ConnectionStats{})
	assert.Equal(t, 0, len(conns))

	// Should be a no op
	state.(*networkState).cleanupState(time.Now(), false, false)

	clients = state.(*networkState).getClients()
	assert.Equal(t, 1, len(clients))
	assert.Equal(t, "1", clients[0])

	time.Sleep(wait)

	// Should delete the client 1
	state.(*networkState).cleanupState(time.Now(), false, false)

	clients = state.(*networkState).getClients()
	assert.Equal(t, 0, len(clients))
}

func TestLastStats(t *testing.T) {
	client1 := "1"
	client2 := "2"
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
	conns := state.Connections(client1, []ConnectionStats{})
	assert.Equal(t, 0, len(conns))

	// Same for an other client
	conns = state.Connections(client2, []ConnectionStats{})
	assert.Equal(t, 0, len(conns))

	// We should have only one connection but with last stats equal to monotonic
	conns = state.Connections(client1, []ConnectionStats{conn})
	assert.Equal(t, 1, len(conns))
	assert.Equal(t, conn.MonotonicSentBytes, conns[0].LastSentBytes)
	assert.Equal(t, conn.MonotonicRecvBytes, conns[0].LastRecvBytes)
	assert.Equal(t, conn.MonotonicRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn.MonotonicRetransmits, conns[0].MonotonicRetransmits)

	// This client didn't collect the first connection so last stats = monotonic
	conns = state.Connections(client2, []ConnectionStats{conn2})
	assert.Equal(t, 1, len(conns))
	assert.Equal(t, conn2.MonotonicSentBytes, conns[0].LastSentBytes)
	assert.Equal(t, conn2.MonotonicRecvBytes, conns[0].LastRecvBytes)
	assert.Equal(t, conn2.MonotonicRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn2.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn2.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn2.MonotonicRetransmits, conns[0].MonotonicRetransmits)

	// client 1 should have conn3 - conn1 since it did not collected conn2
	conns = state.Connections(client1, []ConnectionStats{conn3})
	assert.Equal(t, 1, len(conns))
	assert.Equal(t, 2*dSent, conns[0].LastSentBytes)
	assert.Equal(t, 2*dRecv, conns[0].LastRecvBytes)
	assert.Equal(t, 2*dRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn3.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn3.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn3.MonotonicRetransmits, conns[0].MonotonicRetransmits)

	// client 2 should have conn3 - conn2
	conns = state.Connections(client2, []ConnectionStats{conn3})
	assert.Equal(t, 1, len(conns))
	assert.Equal(t, dSent, conns[0].LastSentBytes)
	assert.Equal(t, dRecv, conns[0].LastRecvBytes)
	assert.Equal(t, dRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn3.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn3.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn3.MonotonicRetransmits, conns[0].MonotonicRetransmits)
}

func TestLastStatsForClosedConnection(t *testing.T) {
	clientID := "1"
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
	conns := state.Connections(clientID, []ConnectionStats{})
	assert.Equal(t, 0, len(conns))

	// We should have one connection with last stats equal to monotonic stats
	conns = state.Connections(clientID, []ConnectionStats{conn})
	assert.Equal(t, 1, len(conns))
	assert.Equal(t, conn.MonotonicSentBytes, conns[0].LastSentBytes)
	assert.Equal(t, conn.MonotonicRecvBytes, conns[0].LastRecvBytes)
	assert.Equal(t, conn.MonotonicRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn.MonotonicRetransmits, conns[0].MonotonicRetransmits)

	state.StoreClosedConnection(conn2)

	// We should have one connection with last stats
	conns = state.Connections(clientID, []ConnectionStats{})

	assert.Equal(t, 1, len(conns))
	assert.Equal(t, dSent, conns[0].LastSentBytes)
	assert.Equal(t, dRecv, conns[0].LastRecvBytes)
	assert.Equal(t, dRetransmits, conns[0].LastRetransmits)
	assert.Equal(t, conn2.MonotonicSentBytes, conns[0].MonotonicSentBytes)
	assert.Equal(t, conn2.MonotonicRecvBytes, conns[0].MonotonicRecvBytes)
	assert.Equal(t, conn2.MonotonicRetransmits, conns[0].MonotonicRetransmits)
}

func TestRaceConditions(t *testing.T) {
	nClients := 10

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
	wg.Add(nClients)

	// Spawn multiple clients to get multiple times
	for i := 1; i <= nClients; i++ {
		go func(c string) {
			defer wg.Done()
			defer state.RemoveClient(c)
			timer := time.NewTimer(1 * time.Second)
			for {
				select {
				case <-timer.C:
					return
				default:
					state.Connections(c, genConns(nConns))
				}
			}
		}(fmt.Sprintf("%d", i))
	}

	wg.Wait()
}

func TestSameKeyEdgeCases(t *testing.T) {
	// For this test all the connections have the same key
	// Each vertical bar represents a collection for a given client
	// Each horizontal bar represents a connection lifespan (from start to end with the number of sent bytes written on top of the line)

	client := "c"
	conn := ConnectionStats{
		Pid:                123,
		Type:               TCP,
		Family:             AFINET,
		Source:             "localhost",
		Dest:               "localhost",
		MonotonicSentBytes: 3,
	}

	t.Run("ShortlivedConnection", func(t *testing.T) {
		// +     3 bytes      +
		// |                  |
		// |   +---------+    |
		// |                  |
		// +                  +

		// c0                 c1

		// We expect:
		// c0: Nothing
		// c1: Monotonic: 3 bytes, Last seen: 3 bytes
		state := NewDefaultNetworkState()

		// First get, we should have nothing
		conns := state.Connections(client, []ConnectionStats{})
		assert.Equal(t, 0, len(conns))

		// Store the connection as closed
		state.StoreClosedConnection(conn)

		// Second get, we should have monotonic and last stats = 3
		conns = state.Connections(client, []ConnectionStats{})
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 3, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 3, int(conns[0].LastSentBytes))
	})

	t.Run("TwoShortlivedConnections", func(t *testing.T) {
		//  +    3 bytes       5 bytes    +
		//  |                             |
		//  |    +-----+       +-----+    |
		//  |                             |
		//  +                             +

		//  c0                            c1

		// We expect:
		// c0: Nothing
		// c1: Monotonic: 8 bytes, Last seenL 8 bytes

		state := NewDefaultNetworkState()

		// First get, we should have nothing
		conns := state.Connections(client, []ConnectionStats{})
		assert.Equal(t, 0, len(conns))

		// Store the connection as closed
		state.StoreClosedConnection(conn)

		conn2 := conn
		conn2.MonotonicSentBytes = 5
		conn2.LastUpdateEpoch++
		// Store the connection another time
		state.StoreClosedConnection(conn2)

		// Second get, we should have monotonic and last stats = 8
		conns = state.Connections(client, []ConnectionStats{})
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 8, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 8, int(conns[0].LastSentBytes))
	})

	t.Run("TwoShortlivedConnectionsCrossing", func(t *testing.T) {
		// +    3 bytes    2 b  +  3 bytes    1 b +   2 b        +
		// |                    |                 |              |
		// |    +-----+    +-----------+      +------------+     |
		// |                    |                 |              |
		// +                    +                 +              +

		// c0                   c1                c2             c3
		// We expect:

		// c0: Nothing
		// c1: Monotonic: 5 bytes, Last seen: 5 bytes
		// c2: Monotonic: 6 bytes, Last seen: 4 bytes
		// c3: Monotonic: 3 bytes, Last seen: 2 bytes

		state := NewDefaultNetworkState()

		// First get, we should have nothing
		conns := state.Connections(client, []ConnectionStats{})
		assert.Equal(t, 0, len(conns))

		// Store the connection as closed
		state.StoreClosedConnection(conn)

		conn2 := conn
		conn2.MonotonicSentBytes = 2
		conn2.LastUpdateEpoch++
		// Store the connection as an opened connection
		cs := []ConnectionStats{conn2}

		// Second get, we should have monotonic and last stats = 5
		conns = state.Connections(client, cs)
		require.Equal(t, 1, len(conns))
		assert.Equal(t, 5, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 5, int(conns[0].LastSentBytes))

		// Store the connection as closed
		conn2.MonotonicSentBytes += 3
		conn2.LastUpdateEpoch++
		state.StoreClosedConnection(conn2)

		// Store the connection again
		conn3 := conn2
		conn3.MonotonicSentBytes = 1
		conn3.LastUpdateEpoch++
		cs = []ConnectionStats{conn3}

		// Third get, we should have monotonic = 6 and last stats = 4
		conns = state.Connections(client, cs)
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 6, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 4, int(conns[0].LastSentBytes))

		// Store the connection as closed
		conn3.MonotonicSentBytes += 2
		state.StoreClosedConnection(conn3)

		// 4th get, we should have monotonic = 3 and last stats = 2
		conns = state.Connections(client, []ConnectionStats{})
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 3, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 2, int(conns[0].LastSentBytes))
	})

	t.Run("ConnectionCrossing", func(t *testing.T) {
		// 3 b  +  5 bytes        +
		//      |                 |
		// +-----------+          |
		//      |                 |
		//      +                 +

		//     c0                c1
		// We expect:

		// c0: Monotonic: 3 bytes, Last seen: 3 bytes
		// c1: Monotonic: 8 bytes, Last seen: 5 bytes

		state := NewDefaultNetworkState()

		// this is to register we should not have anything
		conns := state.Connections(client, []ConnectionStats{})
		assert.Equal(t, 0, len(conns))

		// Store the connection as opened
		cs := []ConnectionStats{conn}

		// First get, we should have monotonic = 3 and last seen = 3
		conns = state.Connections(client, cs)
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 3, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 3, int(conns[0].LastSentBytes))

		// Store the connection as closed
		conn2 := conn
		conn2.MonotonicSentBytes = 8
		state.StoreClosedConnection(conn2)

		// Second get, we should have monotonic = 8 and last stats = 5
		conns = state.Connections(client, []ConnectionStats{})
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 8, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 5, int(conns[0].LastSentBytes))
	})

	t.Run("TwoShortlivedConnectionsCrossingWithTwoClients", func(t *testing.T) {
		//              +    3 bytes    2 b  +  3 bytes    1 b +   2 b        +
		//              |                    |                 |              |
		// client c     |    +-----+    +-----------+      +------------+     |
		//              |                    |                 |              |
		//              +                    +                 +              +
		//
		//              c0                   c1                c2             c3
		//
		//
		//              +    3 bytes  +  3 b    +  2 b      2 b     +  1 b         +
		//              |             |         |                   |              |
		// client d     |    +-----+  |  +----------+      +------------+          |
		//              |             |         |                   |              |
		//              +             +         +                   +              +
		//
		//              d0            d1        d2                  d3             d4

		// We expect:
		// c0: Nothing
		// d0: Nothing
		// d1: Monotonic: 3 bytes, Last seen: 3 bytes (this connection started after closed + collect, so we reset monotonic)
		// c1: Monotonic: 5 bytes, Last seen: 5 bytes
		// d2: Monotonic: 3 bytes, Last seen 3 bytes
		// c2: Monotonic: 6 bytes, Last seen: 4 bytes
		// d3: Monotonic: 7 bytes, Last seen 4 bytes
		// c3: Monotonic: 3 bytes, Last seen: 2 bytes
		// d4: Monotonic: 3 bytes, Last seen: 1 bytes

		clientD := "d"

		state := NewDefaultNetworkState()

		// First get for client c, we should have nothing
		conns := state.Connections(client, []ConnectionStats{})
		assert.Equal(t, 0, len(conns))

		// First get for client d, we should have nothing
		conns = state.Connections(clientD, []ConnectionStats{})
		assert.Equal(t, 0, len(conns))

		// Store the connection as closed
		state.StoreClosedConnection(conn)

		// Second get for client d we should have monotonic and last stats = 3
		conns = state.Connections(clientD, []ConnectionStats{})
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 3, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 3, int(conns[0].LastSentBytes))

		// Store the connection as an opened connection
		conn2 := conn
		conn2.MonotonicSentBytes = 2
		conn2.LastUpdateEpoch++
		cs := []ConnectionStats{conn2}

		// Second get, for client c we should have monotonic and last stats = 5
		conns = state.Connections(client, cs)
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 5, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 5, int(conns[0].LastSentBytes))

		// Store the connection as an opened connection
		conn2.MonotonicSentBytes += 1
		conn2.LastUpdateEpoch++
		cs = []ConnectionStats{conn2}

		// Third get, for client d we should have monotonic = 3 and last stats = 3
		conns = state.Connections(clientD, cs)
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 3, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 3, int(conns[0].LastSentBytes))

		// Store the connection as closed
		conn2.MonotonicSentBytes += 2
		conn2.LastUpdateEpoch++
		state.StoreClosedConnection(conn2)

		// Store the connection again
		conn3 := conn2
		conn3.MonotonicSentBytes = 1
		conn3.LastUpdateEpoch++
		cs = []ConnectionStats{conn3}

		// Third get, for client c, we should have monotonic = 6 and last stats = 4
		conns = state.Connections(client, cs)
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 6, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 4, int(conns[0].LastSentBytes))

		// Store the connection again
		conn3.MonotonicSentBytes += 1
		conn3.LastUpdateEpoch++
		cs = []ConnectionStats{conn3}

		// 4th get, for client d, we should have monotonic = 7 and last stats = 4
		conns = state.Connections(clientD, cs)
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 7, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 4, int(conns[0].LastSentBytes))

		// Store the connection as closed
		conn3.MonotonicSentBytes += 1
		conn3.LastUpdateEpoch++
		state.StoreClosedConnection(conn3)

		// 4th get, for client c we should have monotonic = 3 and last stats = 2
		conns = state.Connections(client, []ConnectionStats{})
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 3, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 2, int(conns[0].LastSentBytes))

		// 5th get, for client d we should have monotonic = 3 and last stats = 1
		conns = state.Connections(clientD, []ConnectionStats{})
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 3, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 1, int(conns[0].LastSentBytes))
	})

	t.Run("ShortlivedConnectionCrossingWithThreeClients", func(t *testing.T) {
		//              +    3 bytes    2 b  +  3 bytes
		//              |                    |
		// client c     |    +-----+    +-----------+
		//              |                    |
		//              +                    +
		//
		//              c0                   c1
		//
		//
		//              +    3 bytes  +  3 b    +  2 b
		//              |             |         |
		// client d     |    +-----+  |  +----------+
		//              |             |         |
		//              +             +         +
		//
		//              d0            d1        d2
		//
		//
		//              +    2 b + 1b  +    5 bytes   +
		//              |        |     |              |
		// client e     |    +-----+   | +---------+  |
		//              |        |     |              |
		//              +        +     +              +
		//
		//              e0       e1    e2             e3

		// We expect:
		// c0, d0, e0: Nothing
		// e1: Monotonic: 2 bytes, Last seen 2 bytes
		// d1: Monotonic 3 bytes, Last seen: 3 bytes
		// e2: Monotonic: 3 bytes, Last seen: 1 bytes
		// c1: Monotonic: 5 bytes, Last seen: 5 bytes
		// d2: Monotonic: 3 bytes, Last seen 3 bytes
		// e3: Monotonic: 5 bytes, Last seen: 5 bytes

		clientD := "d"
		clientE := "e"

		state := NewDefaultNetworkState()

		// First get for client c, we should have nothing
		conns := state.Connections(client, []ConnectionStats{})
		assert.Equal(t, 0, len(conns))

		// First get for client d, we should have nothing
		conns = state.Connections(clientD, []ConnectionStats{})
		assert.Equal(t, 0, len(conns))

		// First get for client e, we should have nothing
		conns = state.Connections(clientE, []ConnectionStats{})
		assert.Equal(t, 0, len(conns))

		// Store the connection
		conn.MonotonicSentBytes = 2
		conn.LastUpdateEpoch++
		cs := []ConnectionStats{conn}

		// Second get for client e we should have monotonic and last stats = 2
		conns = state.Connections(clientE, cs)
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 2, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 2, int(conns[0].LastSentBytes))

		// Store the connection as closed
		conn.MonotonicSentBytes += 1
		conn.LastUpdateEpoch++
		state.StoreClosedConnection(conn)

		// Second get for client d we should have monotonic and last stats = 3
		conns = state.Connections(clientD, []ConnectionStats{})
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 3, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 3, int(conns[0].LastSentBytes))

		// Third get for client e we should have monotonic = 3and last stats = 1
		conns = state.Connections(clientE, []ConnectionStats{})
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 3, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 1, int(conns[0].LastSentBytes))

		// Store the connection as an opened connection
		conn2 := conn
		conn2.MonotonicSentBytes = 2
		conn2.LastUpdateEpoch++
		cs = []ConnectionStats{conn2}

		// Second get, for client c we should have monotonic and last stats = 5
		conns = state.Connections(client, cs)
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 5, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 5, int(conns[0].LastSentBytes))

		// Store the connection as an opened connection
		conn2.MonotonicSentBytes += 1
		conn2.LastUpdateEpoch++
		cs = []ConnectionStats{conn2}

		// Third get, for client d we should have monotonic = 3 and last stats = 3
		conns = state.Connections(clientD, cs)
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 3, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 3, int(conns[0].LastSentBytes))

		// Store the connection as closed
		conn2.MonotonicSentBytes += 2
		conn2.LastUpdateEpoch++
		state.StoreClosedConnection(conn2)

		// 4th get, for client e we should have monotonic = 5 and last stats = 5
		conns = state.Connections(clientE, []ConnectionStats{})
		assert.Equal(t, 1, len(conns))
		assert.Equal(t, 5, int(conns[0].MonotonicSentBytes))
		assert.Equal(t, 5, int(conns[0].LastSentBytes))
	})
}

func generateRandConnections(n int) []ConnectionStats {
	cs := make([]ConnectionStats, 0, n)
	for i := 0; i < n; i++ {
		cs = append(cs, ConnectionStats{
			Pid:                  123,
			Type:                 TCP,
			Family:               AFINET,
			Source:               "localhost",
			Dest:                 "localhost",
			SPort:                uint16(rand.Intn(math.MaxUint16)),
			DPort:                uint16(rand.Intn(math.MaxUint16)),
			MonotonicRecvBytes:   rand.Uint64(),
			MonotonicSentBytes:   rand.Uint64(),
			MonotonicRetransmits: rand.Uint32(),
		})
	}
	return cs
}
