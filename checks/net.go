package checks

import (
	"bytes"
	"time"

	log "github.com/cihub/seelog"

	"github.com/DataDog/tcptracer-bpf/pkg/tracer"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
)

// Connections is a singleton ConnectionsCheck.
var Connections = &ConnectionsCheck{}

// ConnectionsCheck collects statistics about live TCP and UDP connections.
type ConnectionsCheck struct {
	tracer    *tracer.Tracer
	supported bool

	prevCheckConns []tracer.ConnectionStats
	prevCheckTime  time.Time

	buf *bytes.Buffer // Internal buffer
}

// Init initializes a ConnectionsCheck instance.
func (c *ConnectionsCheck) Init(cfg *config.AgentConfig, sysInfo *model.SystemInfo) {
	var err error

	// Checking whether the current kernel version is supported by the tracer
	if c.supported, err = tracer.IsTracerSupportedByOS(); err != nil {
		// err is always returned when false, so the above catches the !ok case as well
		log.Warnf("network tracer unsupported by OS: %s", err)
		return
	}

	t, err := tracer.NewTracer()
	if err != nil {
		log.Errorf("failed to create network tracer: %s", err)
		return
	}

	c.tracer = t
	c.tracer.Start()
	c.buf = new(bytes.Buffer)
}

// Name returns the name of the ConnectionsCheck.
func (c *ConnectionsCheck) Name() string { return "connections" }

// Endpoint returns the endpoint where this check is submitted.
func (c *ConnectionsCheck) Endpoint() string { return "/api/v1/collector" }

// RealTime indicates if this check only runs in real-time mode.
func (c *ConnectionsCheck) RealTime() bool { return false }

// Run runs the ConnectionsCheck to collect the live TCP connections on the
// system. Currently only linux systems are supported as eBPF is used to gather
// this information. For each connection we'll return a `model.Connection`
// that will be bundled up into a `CollectorConnections`.
// See agent.proto for the schema of the message and models.
func (c *ConnectionsCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	if !c.supported || c.tracer == nil {
		return nil, nil
	}

	start := time.Now()

	conns, err := c.tracer.GetActiveConnections()
	if err != nil {
		if err == tracer.ErrNotImplemented {
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
	lastConnByKey := make(map[string]tracer.ConnectionStats)
	for _, conn := range c.prevCheckConns {
		if b, err := conn.ByteKey(c.buf); err == nil {
			lastConnByKey[string(b)] = conn
		} else {
			log.Debugf("failed to create connection byte key: %s", err)
		}
	}

	log.Infof("collected connections in %s", time.Since(start))
	return batchConnections(cfg, groupID, c.formatConnections(conns, lastConnByKey, c.prevCheckTime)), nil
}

// Connections are split up into a chunks of at most 100 connections per message to
// limit the message size on intake.
func (c *ConnectionsCheck) formatConnections(conns []tracer.ConnectionStats, lastConns map[string]tracer.ConnectionStats, lastCheckTime time.Time) []*model.Connection {
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
				Ip:   conn.Source,
				Port: int32(conn.SPort),
			},
			Raddr: &model.Addr{
				Ip:   conn.Dest,
				Port: int32(conn.DPort),
			},
			BytesSent:     calculateRate(conn.SendBytes, lastConns[key].SendBytes, lastCheckTime),
			BytesRecieved: calculateRate(conn.RecvBytes, lastConns[key].RecvBytes, lastCheckTime),
		})
	}
	c.prevCheckConns = conns
	return cxs
}

func formatFamily(f tracer.ConnectionFamily) model.ConnectionFamily {
	switch f {
	case tracer.AF_INET:
		return model.ConnectionFamily_v4
	case tracer.AF_INET6:
		return model.ConnectionFamily_v6
	default:
		return -1
	}
}

func formatType(f tracer.ConnectionType) model.ConnectionType {
	switch f {
	case tracer.TCP:
		return model.ConnectionType_tcp
	case tracer.UDP:
		return model.ConnectionType_udp
	default:
		return -1
	}
}

func batchConnections(cfg *config.AgentConfig, groupID int32, cxs []*model.Connection) []model.MessageBody {
	groupSize := groupSize(len(cxs), cfg.MaxPerMessage)
	batches := make([]model.MessageBody, 0, groupSize)

	for len(cxs) > 0 {
		batchSize := min(cfg.MaxPerMessage, len(cxs))
		batches = append(batches, &model.CollectorConnections{
			HostName:    cfg.HostName,
			Connections: cxs[:batchSize],
			GroupId:     groupID,
			GroupSize:   groupSize,
		})
		cxs = cxs[batchSize:]
	}
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

func connectionPIDs(conns []tracer.ConnectionStats) []uint32 {
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
