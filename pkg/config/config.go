package config

import (
	ddconfig "github.com/StackVista/stackstate-agent/pkg/config"
	"os"
	"strings"
)

var Datadog ddconfig.Config

func init() {
	// Configure Datadog global configuration
	Datadog = ddconfig.NewConfig("stackstate", "STS", strings.NewReplacer(".", "_"))
	// Configuration defaults
	ddconfig.InitConfig(Datadog)

}

// IsContainerized returns whether the Agent is running on a Docker container
func IsContainerized() bool {
	return os.Getenv("DOCKER_STS_AGENT") != ""
}

// GetMainEndpoint returns the main DD URL defined in the config, based on `site` and the prefix, or ddURLKey
func GetMainEndpoint(prefix string, ddURLKey string) string {
	return ddconfig.GetMainEndpointWithConfig(Datadog, prefix, ddURLKey)
}

func Load() (*ddconfig.Warnings, error) {
	return ddconfig.LoadStackstate(Datadog)
}
