package checks

import (
	"bytes"
	"fmt"
	"github.com/DataDog/sketches-go/ddsketch"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/patrickmn/go-cache"
	"math"
	"sort"
	"strings"
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
				err := fillNetworkRelationCache(cfg.HostName, c, connStats[0], lastRun.Add(-5*time.Minute).Unix(), lastRun.Unix())
				assert.NoError(t, err)
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
				err := fillNetworkRelationCache(cfg.HostName, c, conn, lastRun.Add(-5*time.Minute).Unix(), lastRun.Unix())
				assert.NoError(t, err)
			},
			expected:                         true,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should filter a relation that has not been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *cache.Cache) {
				err := fillNetworkRelationCache(cfg.HostName, c, connStats[0], lastRun.Add(-5*time.Second).Unix(), lastRun.Unix())
				assert.NoError(t, err)
			},
			expected:                         false,
			networkRelationShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should not filter a relation when the networkRelationShortLivedEnabled is set to false"),
			prepCache: func(c *cache.Cache) {
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

func fillNetworkRelationCache(hostname string, c *cache.Cache, conn common.ConnectionStats, firstObserved, lastObserved int64) error {
	relationID, err := CreateNetworkRelationIdentifier(hostname, conn)
	if err != nil {
		return err
	}
	cachedRelation := &NetworkRelationCache{
		ConnectionMetrics: ConnectionMetrics{
			SendBytes: conn.SendBytes,
			RecvBytes: conn.RecvBytes,
		},
		FirstObserved: firstObserved,
		LastObserved:  lastObserved,
	}
	c.Set(relationID, cachedRelation, cache.DefaultExpiration)
	return nil
}

func TestDDsketchDecode(t *testing.T) {
	testData := []byte{
		0x0a, 0x09, 0x09, 0xfd, 0x4a, 0x81, 0x5a, 0xbf, 0x52, 0xf0, 0x3f, 0x12, 0x0a, 0x12, 0x08, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0x1a, 0x00,
	}
	ddsk, err := decodeDDSketch(testData)
	assert.NoError(t, err)
	assert.NotNil(t, ddsk)
	assert.Equal(t, 1, int(ddsk.GetCount()))
	maxValue, err := ddsk.GetMaxValue()
	assert.NoError(t, err)
	assert.Equal(t, 1009, int(maxValue*1000))
}

func TestFormatMetrics(t *testing.T) {
	httpMetrics := []common.HttpMetric{
		{
			StatusCode: 200,
			DDSketch:   makeDDSketch(1),
		},
		{
			StatusCode: 201,
			DDSketch:   makeDDSketch(2),
		},
		{
			StatusCode: 400,
			DDSketch:   makeDDSketch(3),
		},
		{
			StatusCode: 501,
			DDSketch:   makeDDSketch(4),
		},
	}

	previousMetrics := HttpConnectionMetrics{ReqCounts: map[string]int{}}

	metrics, accumulatedMetrics := formatMetrics(httpMetrics, previousMetrics)

	sort.Slice(metrics, func(i, j int) bool {
		switch strings.Compare(metrics[i].Name, metrics[j].Name) {
		case -1:
			return false
		case 1:
			return true
		default:
			return strings.Compare(metrics[i].Tags[0].Value, metrics[j].Tags[0].Value) < 0
		}
	})

	expected := []string{"200", "201", "2xx", "400", "4xx", "501", "5xx", "any", "success", "1xx", "200", "201", "2xx", "3xx", "400", "4xx", "501", "5xx", "any", "success"}
	actual := []string{}
	for _, m := range metrics {
		actual = append(actual, m.Tags[0].Value)
	}
	assert.Equal(t, expected, actual)

	assertHTTPResponseTimeConnectionMetric(t, metrics[0], "200", 1, 1, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[1], "201", 2, 2, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[2], "2xx", 1, 2, 2)
	assertHTTPResponseTimeConnectionMetric(t, metrics[3], "400", 3, 3, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[4], "4xx", 3, 3, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[5], "501", 4, 4, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[6], "5xx", 4, 4, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[7], "any", 1, 4, 4)
	assertHTTPResponseTimeConnectionMetric(t, metrics[8], "success", 1, 2, 2)

	assertHTTPRequestCountConnectionMetric(t, metrics[9], "1xx", 0)
	assertHTTPRequestCountConnectionMetric(t, metrics[10], "200", 1)
	assertHTTPRequestCountConnectionMetric(t, metrics[11], "201", 1)
	assertHTTPRequestCountConnectionMetric(t, metrics[12], "2xx", 2)
	assertHTTPRequestCountConnectionMetric(t, metrics[13], "3xx", 0)
	assertHTTPRequestCountConnectionMetric(t, metrics[14], "400", 1)
	assertHTTPRequestCountConnectionMetric(t, metrics[15], "4xx", 1)
	assertHTTPRequestCountConnectionMetric(t, metrics[16], "501", 1)
	assertHTTPRequestCountConnectionMetric(t, metrics[17], "5xx", 1)
	assertHTTPRequestCountConnectionMetric(t, metrics[18], "any", 4)
	assertHTTPRequestCountConnectionMetric(t, metrics[19], "success", 2)

	assert.Equal(t, 0, accumulatedMetrics.ReqCounts["1xx"])
	assert.Equal(t, 1, accumulatedMetrics.ReqCounts["200"])
	assert.Equal(t, 1, accumulatedMetrics.ReqCounts["201"])
	assert.Equal(t, 2, accumulatedMetrics.ReqCounts["2xx"])
	assert.Equal(t, 0, accumulatedMetrics.ReqCounts["3xx"])
	assert.Equal(t, 1, accumulatedMetrics.ReqCounts["400"])
	assert.Equal(t, 1, accumulatedMetrics.ReqCounts["4xx"])
	assert.Equal(t, 1, accumulatedMetrics.ReqCounts["501"])
	assert.Equal(t, 1, accumulatedMetrics.ReqCounts["5xx"])
	assert.Equal(t, 4, accumulatedMetrics.ReqCounts["any"])
	assert.Equal(t, 2, accumulatedMetrics.ReqCounts["success"])
}

func TestFormatMetrics_AccumulatedMetrics(t *testing.T) {
	httpMetrics := []common.HttpMetric{
		{
			StatusCode: 200,
			DDSketch:   makeDDSketch(1),
		},
		{
			StatusCode: 201,
			DDSketch:   makeDDSketch(2),
		},
		{
			StatusCode: 400,
			DDSketch:   makeDDSketch(3),
		},
		{
			StatusCode: 501,
			DDSketch:   makeDDSketch(4),
		},
	}

	previousMetrics := HttpConnectionMetrics{ReqCounts: map[string]int{
		"200":     5,
		"2xx":     7,
		"401":     2,
		"4xx":     2,
		"502":     3,
		"5xx":     4,
		"any":     12,
		"success": 8,
	}}

	metrics, accumulatedMetrics := formatMetrics(httpMetrics, previousMetrics)

	sort.Slice(metrics, func(i, j int) bool {
		switch strings.Compare(metrics[i].Name, metrics[j].Name) {
		case -1:
			return false
		case 1:
			return true
		default:
			return strings.Compare(metrics[i].Tags[0].Value, metrics[j].Tags[0].Value) < 0
		}
	})

	expected := []string{"200", "201", "2xx", "400", "4xx", "501", "5xx", "any", "success", "1xx", "200", "201", "2xx", "3xx", "400", "401", "4xx", "501", "502", "5xx", "any", "success"}
	actual := []string{}
	for _, m := range metrics {
		actual = append(actual, m.Tags[0].Value)
	}
	assert.Equal(t, expected, actual)

	assertHTTPResponseTimeConnectionMetric(t, metrics[0], "200", 1, 1, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[1], "201", 2, 2, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[2], "2xx", 1, 2, 2)
	assertHTTPResponseTimeConnectionMetric(t, metrics[3], "400", 3, 3, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[4], "4xx", 3, 3, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[5], "501", 4, 4, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[6], "5xx", 4, 4, 1)
	assertHTTPResponseTimeConnectionMetric(t, metrics[7], "any", 1, 4, 4)
	assertHTTPResponseTimeConnectionMetric(t, metrics[8], "success", 1, 2, 2)

	assertHTTPRequestCountConnectionMetric(t, metrics[9], "1xx", 0)
	assertHTTPRequestCountConnectionMetric(t, metrics[10], "200", 5+1)
	assertHTTPRequestCountConnectionMetric(t, metrics[11], "201", 1)
	assertHTTPRequestCountConnectionMetric(t, metrics[12], "2xx", 7+2)
	assertHTTPRequestCountConnectionMetric(t, metrics[13], "3xx", 0)
	assertHTTPRequestCountConnectionMetric(t, metrics[14], "400", 1)
	assertHTTPRequestCountConnectionMetric(t, metrics[15], "401", 2)
	assertHTTPRequestCountConnectionMetric(t, metrics[16], "4xx", 3)
	assertHTTPRequestCountConnectionMetric(t, metrics[17], "501", 1)
	assertHTTPRequestCountConnectionMetric(t, metrics[18], "502", 3)
	assertHTTPRequestCountConnectionMetric(t, metrics[19], "5xx", 4+1)
	assertHTTPRequestCountConnectionMetric(t, metrics[20], "any", 12+4)
	assertHTTPRequestCountConnectionMetric(t, metrics[21], "success", 8+2)

	assert.Equal(t, 0, accumulatedMetrics.ReqCounts["1xx"])
	assert.Equal(t, 5+1, accumulatedMetrics.ReqCounts["200"])
	assert.Equal(t, 1, accumulatedMetrics.ReqCounts["201"])
	assert.Equal(t, 7+2, accumulatedMetrics.ReqCounts["2xx"])
	assert.Equal(t, 0, accumulatedMetrics.ReqCounts["3xx"])
	assert.Equal(t, 1, accumulatedMetrics.ReqCounts["400"])
	assert.Equal(t, 2, accumulatedMetrics.ReqCounts["401"])
	assert.Equal(t, 3, accumulatedMetrics.ReqCounts["4xx"])
	assert.Equal(t, 1, accumulatedMetrics.ReqCounts["501"])
	assert.Equal(t, 3, accumulatedMetrics.ReqCounts["502"])
	assert.Equal(t, 4+1, accumulatedMetrics.ReqCounts["5xx"])
	assert.Equal(t, 12+4, accumulatedMetrics.ReqCounts["any"])
	assert.Equal(t, 8+2, accumulatedMetrics.ReqCounts["success"])
}

func assertHTTPResponseTimeConnectionMetric(t *testing.T, formattedMetric *model.ConnectionMetric, statusCode string, min int, max int, total int) {
	assert.Equal(t, "http_response_time", formattedMetric.Name)
	codeIsOk := assert.Equal(t, []*model.ConnectionMetricTag{
		{Key: "code", Value: statusCode},
	}, formattedMetric.Tags)
	if codeIsOk {
		actualSketch, err := decodeDDSketch(formattedMetric.Value.GetDdsketchHistogram())
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

func assertHTTPRequestCountConnectionMetric(t *testing.T, formattedMetric *model.ConnectionMetric, statusCode string, expectedCount float64) {
	assert.Equal(t, "http_request_count", formattedMetric.Name)
	codeIsOk := assert.Equal(t, []*model.ConnectionMetricTag{
		{Key: "code", Value: statusCode},
	}, formattedMetric.Tags)
	if codeIsOk {
		assert.Equal(t, expectedCount, formattedMetric.Value.GetNumber())
	}
}

func makeDDSketch(responseTimes ...float64) []byte {
	testDDSketch, _ := ddsketch.NewDefaultDDSketch(0.01)
	for _, rt := range responseTimes {
		testDDSketch.Add(rt)
	}
	sketch, _ := marshalDDSketch(testDDSketch)
	return sketch
}
