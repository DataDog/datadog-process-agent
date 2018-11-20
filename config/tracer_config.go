package config

import (
	"github.com/DataDog/tcptracer-bpf/pkg/tracer"
	log "github.com/cihub/seelog"
)

func TracerConfigFromConfig(cfg *AgentConfig) *tracer.Config {
	tracerConfig := tracer.NewDefaultConfig()

	if !tracerConfig.TraceIPv6Connections {
		log.Info("network tracer IPv6 tracing disabled by network-tracer")
	} else if cfg.DisableIPv6Tracing {
		tracerConfig.TraceIPv6Connections = false
		log.Info("network tracer IPv6 tracing disabled by configuration")
	}

	if cfg.DisableUDPTracing {
		tracerConfig.CollectUDPConns = false
		log.Info("network tracer UDP tracing disabled by configuration")
	}

	if cfg.DisableTCPTracing {
		tracerConfig.CollectTCPConns = false
		log.Info("network tracer TCP tracing disabled by configuration")
	}

	return tracerConfig
}
