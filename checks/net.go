package checks

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/net"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	log "github.com/cihub/seelog"
	"time"
)

var (
	// Connections is a singleton ConnectionsCheck.
	Connections = &ConnectionsCheck{}

	// ErrTracerStillNotInitialized signals that the tracer is _still_ not ready, so we shouldn't log additional errors
	ErrTracerStillNotInitialized = errors.New("remote tracer is still not initialized")
)

// ConnectionsCheck collects statistics about live TCP and UDP connections.
type ConnectionsCheck struct {
	// Local network tracer
	useLocalTracer bool
	localTracer    tracer.Tracer

	prevCheckConns []common.ConnectionStats
	prevCheckTime  time.Time

	buf *bytes.Buffer // Internal buffer
}

// Name returns the name of the ConnectionsCheck.
func (c *ConnectionsCheck) Name() string { return "connections" }

// Endpoint returns the endpoint where this check is submitted.
func (c *ConnectionsCheck) Endpoint() string { return "/api/v1/connections" }

// RealTime indicates if this check only runs in real-time mode.
func (c *ConnectionsCheck) RealTime() bool { return false }

// Run runs the ConnectionsCheck to collect the live TCP connections on the
// system. Currently only linux systems are supported as eBPF is used to gather
// this information. For each connection we'll return a `model.Connection`
// that will be bundled up into a `CollectorConnections`.
// See agent.proto for the schema of the message and models.
func (c *ConnectionsCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	// If local tracer failed to initialize, so we shouldn't be doing any checks
	if c.useLocalTracer && c.localTracer == nil {
		return nil, nil
	}

	start := time.Now()

	conns, err := c.getConnections()
	if err != nil {
		// If the tracer is not initialized, or still not initialized, then we want to exit without error'ing
		if err == common.ErrNotImplemented || err == ErrTracerStillNotInitialized {
			return nil, nil
		}
		return nil, err
	}

	if c.prevCheckConns == nil { // End check early if this is our first run.
		c.prevCheckConns = conns
		c.prevCheckTime = time.Now()
		return nil, nil
	}

	// Temporary map to help find matching connections from previous check
	lastConnByKey := make(map[string]common.ConnectionStats)
	for _, conn := range c.prevCheckConns {
		if b, err := conn.ByteKey(c.buf); err == nil {
			lastConnByKey[string(b)] = conn
		} else {
			log.Debugf("failed to create connection byte key: %s", err)
		}
	}

	log.Debugf("collected connections in %s", time.Since(start))
	return batchConnections(cfg, groupID, c.formatConnections(conns, lastConnByKey, c.prevCheckTime)), nil
}

func (c *ConnectionsCheck) getConnections() ([]common.ConnectionStats, error) {
	if c.useLocalTracer { // If local tracer is set up, use that
		if c.localTracer == nil {
			return nil, fmt.Errorf("using local network tracer, but no tracer was initialized")
		}
		cs, err := c.localTracer.GetConnections()
		return cs.Conns, err
	}

	tu, err := net.GetRemoteNetworkTracerUtil()
	if err != nil {
		if net.ShouldLogTracerUtilError() {
			return nil, err
		}
		return nil, ErrTracerStillNotInitialized
	}

	return tu.GetConnections()
}

// Connections are split up into a chunks of at most 100 connections per message to
// limit the message size on intake.
func (c *ConnectionsCheck) formatConnections(conns []common.ConnectionStats, lastConns map[string]common.ConnectionStats, lastCheckTime time.Time) []*model.Connection {
	// Process create-times required to construct unique process hash keys on the backend
	createTimeForPID := Process.createTimesforPIDs(connectionPIDs(conns))

	cxs := make([]*model.Connection, 0, len(conns))
	for _, conn := range conns {
		b, err := conn.ByteKey(c.buf)
		if err != nil {
			log.Debugf("failed to create connection byte key: %s", err)
			continue
		}

		if _, ok := createTimeForPID[conn.Pid]; !ok {
			continue
		}

		key := string(b)
		cxs = append(cxs, &model.Connection{
			Pid:           int32(conn.Pid),
			PidCreateTime: createTimeForPID[conn.Pid],
			Family:        formatFamily(conn.Family),
			Type:          formatType(conn.Type),
			Laddr: &model.Addr{
				Ip:   conn.Local,
				Port: int32(conn.LocalPort),
			},
			Raddr: &model.Addr{
				Ip:   conn.Remote,
				Port: int32(conn.RemotePort),
			},
			BytesSentPerSecond:     calculateRate(conn.SendBytes, lastConns[key].SendBytes, lastCheckTime),
			BytesReceivedPerSecond: calculateRate(conn.RecvBytes, lastConns[key].RecvBytes, lastCheckTime),
			Direction:              calculateDirection(conn.Direction),
		})
	}
	c.prevCheckConns = conns
	c.prevCheckTime = time.Now()
	return cxs
}

func formatFamily(f common.ConnectionFamily) model.ConnectionFamily {
	switch f {
	case common.AF_INET:
		return model.ConnectionFamily_v4
	case common.AF_INET6:
		return model.ConnectionFamily_v6
	default:
		return -1
	}
}

func formatType(f common.ConnectionType) model.ConnectionType {
	switch f {
	case common.TCP:
		return model.ConnectionType_tcp
	case common.UDP:
		return model.ConnectionType_udp
	default:
		return -1
	}
}

func calculateDirection(d common.Direction) model.ConnectionDirection {
	switch d {
	case common.OUTGOING:
		return model.ConnectionDirection_outgoing
	case common.INCOMING:
		return model.ConnectionDirection_incoming
	default:
		return model.ConnectionDirection_none
	}
}

func batchConnections(cfg *config.AgentConfig, groupID int32, cxs []*model.Connection) []model.MessageBody {
	batches := make([]model.MessageBody, 0, 1)

	// STS: Disable batching for now
	batchSize := min(cfg.MaxPerMessage, len(cxs))
	batches = append(batches, &model.CollectorConnections{
		HostName:    cfg.HostName,
		Connections: cxs[:batchSize],
		GroupId:     groupID,
		GroupSize:   1,
	})

	return batches
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func groupSize(total, maxBatchSize int) int32 {
	groupSize := total / maxBatchSize
	if total%maxBatchSize > 0 {
		groupSize++
	}
	return int32(groupSize)
}

func connectionPIDs(conns []common.ConnectionStats) []uint32 {
	ps := make(map[uint32]struct{}) // Map used to represent a set
	for _, c := range conns {
		ps[c.Pid] = struct{}{}
	}

	pids := make([]uint32, 0, len(ps))
	for pid := range ps {
		pids = append(pids, pid)
	}
	return pids
}
