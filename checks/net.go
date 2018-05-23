package checks

import (
	"time"

	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/weaveworks/tcptracer-bpf/pkg/tracer"
)

// Connections is a singleton ConnectionsCheck.
var Connections = &ConnectionsCheck{}

// ConnectionsCheck collects statistics about live TCP and UDP connections.
type ConnectionsCheck struct {
	tracer  *tracer.Tracer
	enabled bool
}

// Init initializes a ConnectionsCheck instance.
func (c *ConnectionsCheck) Init(cfg *config.AgentConfig, sysInfo *model.SystemInfo) {
	// TODO: Source this by checking both configuration & that we have CAP_SYS_ADMIN privileges
	c.enabled = true

	t, err := tracer.NewTracer()
	if err != nil {
		log.Errorf("failed to create tracer: %s", err)
	}
	c.tracer = t
	t.Start()
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
	if !c.enabled {
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

	log.Infof("collected connections in %s", time.Since(start))
	return []model.MessageBody{&model.CollectorConnections{
		HostName:    cfg.HostName,
		Connections: formatConnections(conns),
	}}, nil
}

// TODO: Break up large connection messages into batches
func formatConnections(conns []tracer.ConnectionStats) []*model.Connection {
	cxs := make([]*model.Connection, 0, len(conns))
	for _, c := range conns {
		cxs = append(cxs, &model.Connection{
			Pid:    int32(c.Pid),
			Family: int32(formatFamily(c.Family)),
			Type:   int32(formatType(c.Type)),
			Laddr: &model.Addr{
				Ip:   c.Source,
				Port: int32(c.SPort),
			},
			Raddr: &model.Addr{
				Ip:   c.Dest,
				Port: int32(c.DPort),
			},
			BytesSent:     int64(c.SendBytes),
			BytesRecieved: int64(c.RecvBytes),
		})
	}
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
