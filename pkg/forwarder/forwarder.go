package forwarder

import (
	"github.com/StackVista/stackstate-agent/cmd/agent/common"
	"github.com/StackVista/stackstate-agent/pkg/aggregator"
	"github.com/StackVista/stackstate-agent/pkg/batcher"
	agentConfig "github.com/StackVista/stackstate-agent/pkg/config"
	"github.com/StackVista/stackstate-agent/pkg/forwarder"
	"github.com/StackVista/stackstate-agent/pkg/serializer"
	"github.com/StackVista/stackstate-agent/pkg/util/flavor"
	"github.com/StackVista/stackstate-process-agent/config"
	log "github.com/cihub/seelog"
)

// ProcessForwarder is a wrapper around the forwarder with the configuration of the process agent
type ProcessForwarder struct {
	forwarder.Forwarder
	*config.AgentConfig
}

// MakeProcessForwarder returns a pointer to a Process Forwarder instance
func MakeProcessForwarder(cfg *config.AgentConfig) *ProcessForwarder {
	// set the common.Forwarder for the internals to work.
	common.Forwarder = forwarder.NewDefaultForwarder(forwarder.NewOptions(extractEndpoints(cfg.APIEndpoints)))
	return &ProcessForwarder{common.Forwarder, cfg}
}

// Start begins running the forwarder, registers the seriliazer and initializes the aggregator.
func (pf ProcessForwarder) Start() {
	log.Debugf("Starting forwarder")
	pf.Forwarder.Start() //nolint:errcheck
	log.Debugf("Forwarder started")

	// setup the aggregator
	s := serializer.NewSerializer(common.Forwarder)
	agg := aggregator.InitAggregator(s, pf.AgentConfig.HostName)
	agg.MetricPrefix = "stackstate"
	// [sts] init the batcher for topology production
	batcher.InitBatcher(s, pf.AgentConfig.HostName, "agent", agentConfig.GetMaxCapacity())
}

// Stop stops the running forwarder, and clears the common.Forwarder global var.
func (pf ProcessForwarder) Stop() {
	log.Debugf("Starting forwarder")
	pf.Forwarder.Stop() //nolint:errcheck
	common.Forwarder.Stop()
	common.Forwarder = nil
	log.Debugf("Forwarder started")
}

func init() {
	// set the flavor to the Process Agent
	flavor.SetFlavor("process_agent")

}

// extractEndpoints creates the keys per domain map for the forwarder.
func extractEndpoints(endpoints []config.APIEndpoint) map[string][]string {
	// setup the forwarder, set up domain -> [apiKeys] from config endpoints
	keysPerDomain := make(map[string][]string)
	for _, apiEndpoint := range endpoints {
		endpoint := apiEndpoint.Endpoint.String()
		if apiKeys, ok := keysPerDomain[endpoint]; ok {
			keysPerDomain[endpoint] = append(apiKeys, apiEndpoint.APIKey)
		} else {
			keysPerDomain[endpoint] = []string{apiEndpoint.APIKey}
		}
	}
	return keysPerDomain
}
