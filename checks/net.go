package checks

import (
	"time"

	"github.com/DataDog/gopsutil/net"
	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
)

func CollectConnections(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	start := time.Now()
	connections, err := net.ConnectionsMax("tcp", cfg.MaxProcFDs)
	if err != nil {
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
