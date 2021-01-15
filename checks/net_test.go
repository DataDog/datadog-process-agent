package checks

import (
	"bytes"
	"fmt"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/patrickmn/go-cache"
	"testing"
	"time"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/stretchr/testify/assert"
)

func makeConnection(pid int32) *model.Connection {
	return &model.Connection{Pid: pid}
}

func TestNetworkConnectionMax(t *testing.T) {
	p := []*model.Connection{
		makeConnection(1),
		makeConnection(2),
		makeConnection(3),
		makeConnection(4),
	}

	cfg := config.NewDefaultAgentConfig()

	for i, tc := range []struct {
		cur, last      []*model.Connection
		maxSize        int
		expectedTotal  int
		expectedChunks int
	}{
		{
			cur:            []*model.Connection{p[0], p[1], p[2]},
			maxSize:        1,
			expectedTotal:  1,
			expectedChunks: 1,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2]},
			maxSize:        2,
			expectedTotal:  2,
			expectedChunks: 1,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2], p[3]},
			maxSize:        10,
			expectedTotal:  4,
			expectedChunks: 1,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2], p[3]},
			maxSize:        3,
			expectedTotal:  3,
			expectedChunks: 1,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2], p[3], p[2], p[3]},
			maxSize:        2,
			expectedTotal:  2,
			expectedChunks: 1,
		},
	} {
		cfg.MaxPerMessage = tc.maxSize
		chunks := batchConnections(cfg, 0, tc.cur)

		assert.Len(t, chunks, tc.expectedChunks, "len %d", i)
		total := 0
		for _, c := range chunks {
			connections := c.(*model.CollectorConnections)
			total += len(connections.Connections)
			assert.Equal(t, int32(tc.expectedChunks), connections.GroupSize, "group size test %d", i)
		}
		assert.Equal(t, tc.expectedTotal, total, "total test %d", i)
	}
}

func makeConnectionStats(pid uint32, local, remote string, localPort, remotePort uint16) common.ConnectionStats {
	return common.ConnectionStats{
		Pid:              pid,
		Type:             common.TCP,
		Family:           common.AF_INET,
		Direction:        common.OUTGOING,
		Local:            local,
		Remote:           remote,
		LocalPort:        localPort,
		RemotePort:       remotePort,
		NetworkNamespace: "ns",
		SendBytes:        0,
		RecvBytes:        0,
		State:            common.ACTIVE,
	}
}

func makeConnectionStatsNoNs(pid uint32, local, remote string, localPort, remotePort uint16) common.ConnectionStats {
	return common.ConnectionStats{
		Pid:        pid,
		Type:       common.TCP,
		Family:     common.AF_INET,
		Direction:  common.OUTGOING,
		Local:      local,
		Remote:     remote,
		LocalPort:  localPort,
		RemotePort: remotePort,
		SendBytes:  0,
		RecvBytes:  0,
		State:      common.ACTIVE,
	}
}

func TestFilterConnectionsByProcess(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	now := time.Now()
	c := &ConnectionsCheck{
		buf:   new(bytes.Buffer),
		cache: cache.New(cfg.NetworkRelationCacheDurationMin, cfg.NetworkRelationCacheDurationMin),
	}

	// create the connection stats
	connStats := []common.ConnectionStats{
		makeConnectionStats(1, "10.0.0.1", "10.0.0.2", 12345, 8080),
		makeConnectionStats(2, "10.0.0.1", "10.0.0.3", 12346, 8080),
		makeConnectionStats(3, "10.0.0.1", "10.0.0.4", 12347, 8080),
		makeConnectionStats(4, "10.0.0.1", "10.0.0.5", 12348, 8080),
	}

	// fill in the relation cache
	for _, conn := range connStats {
		fillNetworkRelationCache(cfg.HostName, c.cache, conn, now.Add(-5*time.Minute).Unix(), now.Unix())
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		// pid 4 filtered by process blacklisting, so we expect no connections for pid 4
	}

	connections := c.formatConnections(cfg, connStats, now.Add(-15*time.Second))

	assert.Len(t, connections, 3)

	pids := make([]int32, 0)
	for _, conn := range connections {
		pids = append(pids, conn.Pid)
	}

	assert.NotContains(t, pids, 4)
}

func TestNetworkConnectionNamespaceKubernetes(t *testing.T) {
	testClusterName := "test-cluster"
	cfg := config.NewDefaultAgentConfig()
	cfg.ClusterName = testClusterName

	now := time.Now()

	c := &ConnectionsCheck{
		buf:   new(bytes.Buffer),
		cache: cache.New(cfg.NetworkRelationCacheDurationMin, cfg.NetworkRelationCacheDurationMin),
	}

	// create the connection stats
	connStats := []common.ConnectionStats{
		makeConnectionStats(1, "10.0.0.1", "10.0.0.2", 12345, 8080),
		makeConnectionStats(2, "10.0.0.1", "10.0.0.3", 12346, 8080),
		makeConnectionStats(3, "10.0.0.1", "10.0.0.4", 12347, 8080),
		makeConnectionStats(4, "10.0.0.1", "10.0.0.5", 12348, 8080),
	}

	// fill in the relation cache
	for _, conn := range connStats {
		namespace := formatNamespace(cfg.ClusterName, cfg.HostName, conn)
		fillNetworkRelationCache(namespace, c.cache, conn, now.Add(-5*time.Minute).Unix(), now.Unix())
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		4: {Pid: 4, CreateTime: now.Add(-5 * time.Minute).Unix()},
	}

	connections := c.formatConnections(cfg, connStats, now.Add(-15*time.Second))

	assert.Len(t, connections, 4)
	for _, c := range connections {
		assert.Contains(t, c.Namespace, testClusterName)
	}

	// clear the changes to Process.lastProcState
	Process.lastProcState = make(map[int32]*model.Process, 0)
}

func TestRelationCache(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	cfg.ShortLivedNetworkRelationQualifierSecs = 500 * time.Millisecond
	cfg.NetworkRelationCacheDurationMin = 600 * time.Millisecond

	now := time.Now()
	c := &ConnectionsCheck{
		buf:   new(bytes.Buffer),
		cache: cache.New(cfg.NetworkRelationCacheDurationMin, cfg.NetworkRelationCacheDurationMin),
	}

	// create the connection stats
	connStats := []common.ConnectionStats{
		makeConnectionStats(1, "10.0.0.1", "10.0.0.2", 12345, 8080),
		makeConnectionStats(2, "10.0.0.1", "10.0.0.3", 12346, 8080),
		makeConnectionStats(3, "10.0.0.1", "10.0.0.4", 12347, 8080),
		makeConnectionStats(4, "10.0.0.1", "10.0.0.5", 12348, 8080),
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		4: {Pid: 4, CreateTime: now.Add(-5 * time.Minute).Unix()},
	}

	// assert an empty cache.
	assert.Zero(t, c.cache.ItemCount(), "Cache should be empty before running")

	// first run on an empty cache; expect no process, but cache should be filled in now.
	firstRun := c.formatConnections(cfg, connStats, now.Add(-15*time.Second))
	assert.Zero(t, len(firstRun), "Connections should be empty when the cache is not present")
	assert.Equal(t, 4, c.cache.ItemCount(), "Cache should contain 4 elements")

	// wait for cfg.ShortLivedNetworkRelationQualifierSecs duration
	time.Sleep(cfg.ShortLivedNetworkRelationQualifierSecs)

	// second run with filled in cache; expect all processes.
	secondRun := c.formatConnections(cfg, connStats, now.Add(-10*time.Second))
	assert.Equal(t, 4, len(secondRun), "Connections should contain 4 elements")
	assert.Equal(t, 4, c.cache.ItemCount(), "Cache should contain 4 elements")

	// delete last connection from the connection stats slice, expect it to be excluded from the connection list, but not the cache
	connStats = connStats[:len(connStats)-1]
	thirdRun := c.formatConnections(cfg, connStats, now.Add(-5*time.Second))
	assert.Equal(t, 3, len(thirdRun), "Connections should contain 3 elements")
	assert.Equal(t, 4, c.cache.ItemCount(), "Cache should contain 4 elements")

	// wait for cfg.NetworkRelationCacheDurationMin + a 250 Millisecond buffer to allow the cache expiration to complete
	time.Sleep(cfg.NetworkRelationCacheDurationMin + 250*time.Millisecond)
	assert.Zero(t, c.cache.ItemCount(), "Cache should be empty again")

	c.cache.Flush()
}

func TestRelationShortLivedFiltering(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	lastRun := time.Now().Add(-5 * time.Second)
	now := time.Now()
	// create the connection stats
	connStats := []common.ConnectionStats{
		makeConnectionStats(1, "10.0.0.1", "10.0.0.2", 12345, 8080),
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
	}

	for _, tc := range []struct {
		name                             string
		prepCache                        func(c *cache.Cache)
		expected                         bool
		networkRelationShortLivedEnabled bool
	}{
		{
			name: fmt.Sprintf("Should not filter a relation that has been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *cache.Cache) {
				fillNetworkRelationCache(cfg.HostName, c, connStats[0], lastRun.Add(-5*time.Minute).Unix(), lastRun.Unix())
			},
			expected:                         true,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should not filter a similar relation that has been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *cache.Cache) {
				// use a "similar" connection; thus we observed a similar connection in the previous run
				conn := makeConnectionStats(1, "10.0.0.1", "10.0.0.2", 54321, 8080)
				fillNetworkRelationCache(cfg.HostName, c, conn, lastRun.Add(-5*time.Minute).Unix(), lastRun.Unix())
			},
			expected:                         true,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should filter a relation that has not been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *cache.Cache) {
				fillNetworkRelationCache(cfg.HostName, c, connStats[0], lastRun.Add(-5*time.Second).Unix(), lastRun.Unix())
			},
			expected:                         false,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should not filter a relation when the networkRelationShortLivedEnabled is set to false"),
			prepCache: func(c *cache.Cache) {
				fillNetworkRelationCache(cfg.HostName, c, connStats[0], lastRun.Add(-5*time.Second).Unix(), lastRun.Unix())
			},
			expected:                         true,
			networkRelationShortLivedEnabled: false,
		},
	} {

		t.Run(tc.name, func(t *testing.T) {
			cfg.EnableShortLivedNetworkRelationFilter = tc.networkRelationShortLivedEnabled

			// Connections Check
			c := &ConnectionsCheck{
				buf:   new(bytes.Buffer),
				cache: cache.New(cfg.NetworkRelationCacheDurationMin, cfg.NetworkRelationCacheDurationMin),
			}
			// fill in the relation cache
			tc.prepCache(c.cache)

			connections := c.formatConnections(cfg, connStats, lastRun)
			var rIDs []string
			for _, conn := range connections {
				rIDs = append(rIDs, conn.ConnectionIdentifier)
			}

			conn := connStats[0]
			relationID := CreateNetworkRelationIdentifier(cfg.HostName, conn)

			if tc.expected {
				assert.Len(t, connections, 1, "The connection should be present in the returned payload for the Connection Check")
				assert.Contains(t, rIDs, relationID, "%s should not be filtered from the relation identifiers for the Connection Check", relationID)
			} else {
				assert.Len(t, connections, 0, "The connection should be filtered in the returned payload for the Connection Check")
				assert.NotContains(t, rIDs, relationID, "%s should be filtered from the relation identifiers for the Connection Check", relationID)
			}

			c.cache.Flush()
		})
	}
}

func TestFormatNamespace(t *testing.T) {
	assert.Equal(t, "", formatNamespace("", "h", makeConnectionStats(1, "10.0.0.1", "10.0.0.2", 12345, 8080)))
	assert.Equal(t, "c", formatNamespace("c", "h", makeConnectionStats(1, "10.0.0.1", "10.0.0.2", 12345, 8080)))
	assert.Equal(t, "c", formatNamespace("c", "h", makeConnectionStats(1, "127.0.0.1", "10.0.0.2", 12345, 8080)))
	assert.Equal(t, "c", formatNamespace("c", "h", makeConnectionStats(1, "10.0.0.1", "127.0.0.1", 12345, 8080)))
	assert.Equal(t, "c:h:ns", formatNamespace("c", "h", makeConnectionStats(1, "127.0.0.1", "127.0.0.1", 12345, 8080)))
	assert.Equal(t, "c:h", formatNamespace("c", "h", makeConnectionStatsNoNs(1, "127.0.0.1", "127.0.0.1", 12345, 8080)))
}

func fillNetworkRelationCache(hostname string, c *cache.Cache, conn common.ConnectionStats, firstObserved, lastObserved int64) {
	relationID := CreateNetworkRelationIdentifier(hostname, conn)
	cachedRelation := &NetworkRelationCache{
		ConnectionMetrics: ConnectionMetrics{
			SendBytes: conn.SendBytes,
			RecvBytes: conn.RecvBytes,
		},
		FirstObserved: firstObserved,
		LastObserved:  lastObserved,
	}
	c.Set(relationID, cachedRelation, cache.DefaultExpiration)
}
