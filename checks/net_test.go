package checks

import (
	"bytes"
	"github.com/DataDog/gopsutil/process"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
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

func TestNetworkConnectionNamespaceKubernetes(t *testing.T) {
	testClusterName := "test-cluster"
	cfg := config.NewDefaultAgentConfig()
	cfg.ClusterName = testClusterName

	now := time.Now()

	c := &ConnectionsCheck{
		buf: new(bytes.Buffer),
	}

	// create the connection stats
	connStats := []common.ConnectionStats{
		makeConnectionStats(1, "10.0.0.1", "10.0.0.2", 12345, 8080),
		makeConnectionStats(2, "10.0.0.1", "10.0.0.3", 12346, 8080),
		makeConnectionStats(3, "10.0.0.1", "10.0.0.4", 12347, 8080),
		makeConnectionStats(4, "10.0.0.1", "10.0.0.5", 12348, 8080),
	}

	// fill in the procs in the lastProcs map to get process create time for the connection mapping
	Process.lastProcs = map[int32]*process.FilledProcess{
		1: &process.FilledProcess{Pid: 1, CreateTime: now.Add(-5 * time.Minute).Unix()},
		2: &process.FilledProcess{Pid: 2, CreateTime: now.Add(-5 * time.Minute).Unix()},
		3: &process.FilledProcess{Pid: 3, CreateTime: now.Add(-5 * time.Minute).Unix()},
		4: &process.FilledProcess{Pid: 4, CreateTime: now.Add(-5 * time.Minute).Unix()},
	}

	connections := c.formatConnections(cfg, connStats, make(map[string]common.ConnectionStats, 0), now.Add(-15*time.Second))

	assert.Len(t, connections, 4)
	for _, c := range connections {
		assert.Contains(t, c.Namespace, testClusterName)
	}

	// clear the changes to Process.lastProcs
	Process.lastProcs = make(map[int32]*process.FilledProcess, 0)
}

func TestFormatNamespace(t *testing.T) {
	assert.Equal(t, "c:n", formatNamespace("c", "n"))
	assert.Equal(t, "c", formatNamespace("c", ""))
	assert.Equal(t, "n", formatNamespace("", "n"))
	assert.Equal(t, "", formatNamespace("", ""))
}
