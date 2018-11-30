package config

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-process-agent/ebpf"
	log "github.com/cihub/seelog"
)

// TracerConfigFromConfig returns a valid tracer-bpf config sourced from our agent config
func TracerConfigFromConfig(cfg *AgentConfig) *ebpf.Config {
	tracerConfig := ebpf.NewDefaultConfig()

	if !isIPv6EnabledOnHost() {
		tracerConfig.CollectIPv6Conns = false
		log.Info("network tracer IPv6 tracing disabled by system")
	} else if cfg.DisableIPv6Tracing {
		tracerConfig.CollectIPv6Conns = false
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

func isIPv6EnabledOnHost() bool {
	_, err := ioutil.ReadFile(hostProc("net/if_inet6"))
	return err == nil
}

// getEnv retrieves the environment variable key. If it does not exist it returns the default.
func getEnv(key string, dfault string, combineWith ...string) string {
	value := os.Getenv(key)
	if value == "" {
		value = dfault
	}

	switch len(combineWith) {
	case 0:
		return value
	case 1:
		return filepath.Join(value, combineWith[0])
	default:
		all := make([]string, len(combineWith)+1)
		all[0] = value
		copy(all[1:], combineWith)
		return filepath.Join(all...)
	}
}

func hostProc(combineWith ...string) string {
	return getEnv("HOST_PROC", "/proc", combineWith...)
}
