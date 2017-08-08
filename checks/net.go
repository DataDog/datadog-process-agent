package checks

import (
	"time"

	"github.com/DataDog/gopsutil/net"
	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/DataDog/datadog-process-agent/util"
)

var Connections = &ConnectionsCheck{}

// ConnectionsCheck collects statistics about live TCP and UDP connections.
type ConnectionsCheck struct{}

// Init initializes a ConnectionsCheck instance.
func (c *ConnectionsCheck) Init(cfg *config.AgentConfig, sysInfo *model.SystemInfo) {}

// Name returns the name of the ConnectionsCheck.
func (c *ConnectionsCheck) Name() string { return "connections" }

// Endpoint returns the endpoint where this check is submitted.
func (c *ConnectionsCheck) Endpoint() string { return "/api/v1/collector" }

// RealTime indicates if this check only runs in real-time mode.
func (c *ConnectionsCheck) RealTime() bool { return false }

// Run runs the ConnectionsCheck to collect the live TCP connections on the
// system. In most POSIX systems we will use the procfs net files to read out
// this information. For each connection we'll return a `model.Connection` that
// will be bundled up into a `CollectorConnections`.
// See agent.proto for the schema of the message and models.
func (c *ConnectionsCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	start := time.Now()
	connections, err := net.ConnectionsMax("tcp", cfg.MaxProcFDs)
	if err != nil && err.Error() == util.ErrNotImplemented.Error() {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	log.Infof("collected connections in %s", time.Now().Sub(start))
	return []model.MessageBody{&model.CollectorConnections{
		HostName:    cfg.HostName,
		Connections: formatConnections(connections),
	}}, nil
}

func formatConnections(stats []net.ConnectionStat) []*model.Connection {
	cxs := make([]*model.Connection, 0, len(stats))
	for _, c := range stats {
		cxs = append(cxs, &model.Connection{
			Pid:    int32(c.Pid),
			Fd:     int32(c.Fd),
			Family: int32(c.Family),
			Type:   int32(c.Type),
			Laddr: &model.Addr{
				Ip:   c.Laddr.IP,
				Port: int32(c.Laddr.Port),
			},
			Raddr: &model.Addr{
				Ip:   c.Raddr.IP,
				Port: int32(c.Raddr.Port),
			},
		})
	}
	return cxs
}
