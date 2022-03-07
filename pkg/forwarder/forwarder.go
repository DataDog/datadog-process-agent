package forwarder

import (
	"github.com/StackVista/stackstate-agent/cmd/agent/common"
	"github.com/StackVista/stackstate-agent/pkg/aggregator"
	"github.com/StackVista/stackstate-agent/pkg/forwarder"
	"github.com/StackVista/stackstate-agent/pkg/serializer"
	"github.com/StackVista/stackstate-agent/pkg/util/flavor"
	"github.com/StackVista/stackstate-process-agent/config"
	log "github.com/cihub/seelog"
)

type ProcessForwarder struct {
	forwarder.Forwarder
	*config.AgentConfig
}

func MakeProcessForwarder(cfg *config.AgentConfig) *ProcessForwarder {
	// set the common.Forwarder for the internals to work.
	common.Forwarder = forwarder.NewDefaultForwarder(forwarder.NewOptions(ExtractEndpoints(cfg.APIEndpoints)))
	return &ProcessForwarder{common.Forwarder, cfg}
}

func (pf ProcessForwarder) Start() {
	log.Debugf("Starting forwarder")
	pf.Forwarder.Start() //nolint:errcheck
	log.Debugf("Forwarder started")

	// setup the aggregator
	s := serializer.NewSerializer(common.Forwarder)
	agg := aggregator.InitAggregator(s, cfg.HostName)
	agg.MetricPrefix = "stackstate"
}

func (pf ProcessForwarder) Stop() {
	log.Debugf("Starting forwarder")
	pf.Forwarder.Stop() //nolint:errcheck
	log.Debugf("Forwarder started")
}

func init() {
	// set the flavor to the Process Agent
	flavor.SetFlavor("process_agent")

}

func ExtractEndpoints(endpoints []config.APIEndpoint) map[string][]string {
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
