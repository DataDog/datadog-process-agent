package checks

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/patrickmn/go-cache"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/stretchr/testify/assert"
)

func makeConnection(pid int32) *model.Connection {
	return &model.Connection{Pid: pid}
}

func TestNetworkConnectionBatching(t *testing.T) {
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
			expectedTotal:  3,
			expectedChunks: 3,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2]},
			maxSize:        2,
			expectedTotal:  3,
			expectedChunks: 2,
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
			expectedTotal:  4,
			expectedChunks: 2,
		},
		{
			cur:            []*model.Connection{p[0], p[1], p[2], p[3], p[2], p[3]},
			maxSize:        2,
			expectedTotal:  6,
			expectedChunks: 3,
		},
	} {
		cfg.MaxConnectionsPerMessage = tc.maxSize
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
		cache: NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin),
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
		err := fillNetworkRelationCache(cfg.HostName, c.cache, conn, now.Add(-5*time.Minute).Unix(), now.Unix())
		assert.NoError(t, err)
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		// pid 4 filtered by process blacklisting, so we expect no connections for pid 4
	}

	connections := c.formatConnections(cfg, connStats, 15*time.Second)

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
		cache: NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin),
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
		err := fillNetworkRelationCache(namespace, c.cache, conn, now.Add(-5*time.Minute).Unix(), now.Unix())
		assert.NoError(t, err)
	}

	// fill in the procs in the lastProcState map to get process create time for the connection mapping
	Process.lastProcState = map[int32]*model.Process{
		1: {Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: {Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: {Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		4: {Pid: 4, CreateTime: now.Add(-5 * time.Minute).Unix()},
	}

	connections := c.formatConnections(cfg, connStats, 15*time.Second)

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
		cache: NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin),
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
	firstRun := c.formatConnections(cfg, connStats, 15*time.Second)
	assert.Zero(t, len(firstRun), "Connections should be empty when the cache is not present")
	assert.Equal(t, 4, c.cache.ItemCount(), "Cache should contain 4 elements")

	// wait for cfg.ShortLivedNetworkRelationQualifierSecs duration
	time.Sleep(cfg.ShortLivedNetworkRelationQualifierSecs)

	// second run with filled in cache; expect all processes.
	secondRun := c.formatConnections(cfg, connStats, 10*time.Second)
	assert.Equal(t, 4, len(secondRun), "Connections should contain 4 elements")
	assert.Equal(t, 4, c.cache.ItemCount(), "Cache should contain 4 elements")

	// delete last connection from the connection stats slice, expect it to be excluded from the connection list, but not the cache
	connStats = connStats[:len(connStats)-1]
	thirdRun := c.formatConnections(cfg, connStats, 5*time.Second)
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
		prepCache                        func(c *NetworkRelationCache)
		expected                         bool
		networkRelationShortLivedEnabled bool
	}{
		{
			name: fmt.Sprintf("Should not filter a relation that has been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *NetworkRelationCache) {
				err := fillNetworkRelationCache(cfg.HostName, c, connStats[0], lastRun.Add(-5*time.Minute).Unix(), lastRun.Unix())
				assert.NoError(t, err)
			},
			expected:                         true,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should not filter a similar relation that has been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *NetworkRelationCache) {
				// use a "similar" connection; thus we observed a similar connection in the previous run
				conn := makeConnectionStats(1, "10.0.0.1", "10.0.0.2", 54321, 8080)
				err := fillNetworkRelationCache(cfg.HostName, c, conn, lastRun.Add(-5*time.Minute).Unix(), lastRun.Unix())
				assert.NoError(t, err)
			},
			expected:                         true,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should filter a relation that has not been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *NetworkRelationCache) {
				err := fillNetworkRelationCache(cfg.HostName, c, connStats[0], lastRun.Add(-5*time.Second).Unix(), lastRun.Unix())
				assert.NoError(t, err)
			},
			expected:                         false,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should not filter a relation when the networkRelationShortLivedEnabled is set to false"),
			prepCache: func(c *NetworkRelationCache) {
				err := fillNetworkRelationCache(cfg.HostName, c, connStats[0], lastRun.Add(-5*time.Second).Unix(), lastRun.Unix())
				assert.NoError(t, err)
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
				cache: NewNetworkRelationCache(cfg.NetworkRelationCacheDurationMin),
			}
			// fill in the relation cache
			tc.prepCache(c.cache)

			connections := c.formatConnections(cfg, connStats, time.Now().Sub(lastRun))
			var rIDs []string
			for _, conn := range connections {
				rIDs = append(rIDs, conn.ConnectionIdentifier)
			}

			conn := connStats[0]
			relationID, err := CreateNetworkRelationIdentifier(cfg.HostName, conn)
			assert.NoError(t, err)

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

func fillNetworkRelationCache(hostname string, c *NetworkRelationCache, conn common.ConnectionStats, firstObserved, lastObserved int64) error {
	relationID, err := CreateNetworkRelationIdentifier(hostname, conn)
	if err != nil {
		return err
	}

	metricsCache := cache.New(c.minCacheDuration, c.minCacheDuration)
	metricsCache.Set(
		fmt.Sprintf("%v", conn.GetConnection()),
		&ConnectionMetrics{
			SendBytes: conn.SendBytes,
			RecvBytes: conn.RecvBytes,
		},
		cache.DefaultExpiration,
	)

	cachedRelation := &NetworkRelationCacheItem{
		connectionMetrics: metricsCache,
		FirstObserved:     firstObserved,
		LastObserved:      lastObserved,
	}
	c.cache.Set(relationID, cachedRelation, cache.DefaultExpiration)
	return nil
}

func TestFormatMetricsEmpty(t *testing.T) {
	metrics := formatMetrics([]common.ConnectionMetric{}, 2*time.Second)
	assert.Len(t, metrics, 0)
}

func TestFormatMetrics(t *testing.T) {
	httpMetrics := []common.ConnectionMetric{
		{
			Name: "http_response_time_seconds",
			Tags: map[string]string{"code": "100"},
			Value: common.ConnectionMetricValue{
				Histogram: &common.Histogram{
					DDSketch: makeDDSketch(),
				},
			},
		},
		{
			Name: "http_response_time_seconds",
			Tags: map[string]string{"code": "200"},
			Value: common.ConnectionMetricValue{
				Histogram: &common.Histogram{
					DDSketch: makeDDSketch(1),
				},
			},
		},
		{
			Name: "http_response_time_seconds",
			Tags: map[string]string{"code": "201"},
			Value: common.ConnectionMetricValue{
				Histogram: &common.Histogram{
					DDSketch: makeDDSketch(2, 2),
				},
			},
		},
		{
			Name: "http_response_time_seconds",
			Tags: map[string]string{"code": "400"},
			Value: common.ConnectionMetricValue{
				Histogram: &common.Histogram{
					DDSketch: makeDDSketch(3, 3, 3),
				},
			},
		},
		{
			Name: "http_response_time_seconds",
			Tags: map[string]string{"code": "501"},
			Value: common.ConnectionMetricValue{
				Histogram: &common.Histogram{
					DDSketch: makeDDSketch(4, 4, 4, 4),
				},
			},
		},
	}

	metrics := formatMetrics(httpMetrics, 2*time.Second)

	sort.Slice(metrics, func(i, j int) bool {
		switch strings.Compare(metrics[i].Name, metrics[j].Name) {
		case -1:
			return false
		case 1:
			return true
		default:
			return strings.Compare(metrics[i].Tags["code"], metrics[j].Tags["code"]) < 0
		}
	})

	expected := []string{"200", "201", "2xx", "400", "4xx", "501", "5xx", "any", "success", "100", "1xx", "200", "201", "2xx", "3xx", "400", "4xx", "501", "5xx", "any", "success"}
	var actual []string
	for _, m := range metrics {
		actual = append(actual, m.Tags["code"])
	}
	assert.Equal(t, expected, actual)

	assertHTTPResponseTimeConnectionMetric(t, metrics[0], "200", 1, 1, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[1], "201", 2, 2, 2)
	assertHTTPResponseTimeConnectionMetric(t, metrics[2], "2xx", 1, 2, 3)
	assertHTTPResponseTimeConnectionMetric(t, metrics[3], "400", 3, 3, 3)
	assertHTTPResponseTimeConnectionMetric(t, metrics[4], "4xx", 3, 3, 3)
	assertHTTPResponseTimeConnectionMetric(t, metrics[5], "501", 4, 4, 4)
	assertHTTPResponseTimeConnectionMetric(t, metrics[6], "5xx", 4, 4, 4)
	assertHTTPResponseTimeConnectionMetric(t, metrics[7], "any", 1, 4, 10)
	assertHTTPResponseTimeConnectionMetric(t, metrics[8], "success", 1, 2, 3)

	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[9], "100", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[10], "1xx", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[11], "200", 0.5)
	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[12], "201", 1)
	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[13], "2xx", 1.5)
	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[14], "3xx", 0)
	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[15], "400", 1.5)
	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[16], "4xx", 1.5)
	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[17], "501", 2)
	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[18], "5xx", 2)
	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[19], "any", 5)
	assertHTTPRequestsPerSecondConnectionMetric(t, metrics[20], "success", 1.5)
}

func assertHTTPResponseTimeConnectionMetric(t *testing.T, formattedMetric *model.ConnectionMetric, statusCode string, min int, max int, total int) {
	assert.Equal(t, "http_response_time_seconds", formattedMetric.Name)
	codeIsOk := assert.Equal(t, map[string]string{
		"code": statusCode,
	}, formattedMetric.Tags)
	if codeIsOk {
		actualSketch, err := ddsketch.FromProto(formattedMetric.Value.GetHistogram())
		assert.NoError(t, err)
		assert.Equal(t, total, int(actualSketch.GetCount()), "Total doesn't match for status code `%s`", statusCode)
		actualMin, err := actualSketch.GetMinValue()
		assert.NoError(t, err)
		assert.Equal(t, min, int(math.Round(actualMin)), "Min doesn't match for status code `%s`", statusCode)
		actualMax, err := actualSketch.GetMaxValue()
		assert.NoError(t, err)
		assert.Equal(t, max, int(math.Round(actualMax)), "Max doesn't match for status code `%s`", statusCode)
	}
}

func assertHTTPRequestsPerSecondConnectionMetric(t *testing.T, formattedMetric *model.ConnectionMetric, statusCode string, expectedRate float64) {
	assert.Equal(t, "http_requests_per_second", formattedMetric.Name)
	codeIsOk := assert.Equal(t, map[string]string{
		"code": statusCode,
	}, formattedMetric.Tags)
	if codeIsOk {
		assert.Equal(t, expectedRate, formattedMetric.Value.GetNumber())
	}
}

func makeDDSketch(responseTimes ...float64) *ddsketch.DDSketch {
	testDDSketch, _ := ddsketch.NewDefaultDDSketch(0.01)
	for _, rt := range responseTimes {
		_ = testDDSketch.Add(rt)
	}
	return testDDSketch
}
