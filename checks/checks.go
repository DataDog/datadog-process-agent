package checks

import (
	"github.com/StackVista/stackstate-agent/pkg/aggregator"
	"github.com/StackVista/stackstate-agent/pkg/collector/check"
	"github.com/StackVista/stackstate-process-agent/cmd/agent/features"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	processUtils "github.com/StackVista/stackstate-process-agent/util"
	log "github.com/cihub/seelog"
	"time"
)

// Check is an interface for Agent checks that collect data. Each check returns
// a specific MessageBody type that will be published to the intake endpoint or
// processed in another way (e.g. printed for debugging).
// Before checks are used you must called Init.
type Check interface {
	Init(cfg *config.AgentConfig, info *model.SystemInfo)
	Name() string
	Endpoint() string
	RealTime() bool
	Run(cfg *config.AgentConfig, features features.Features, groupID int32, currentTime time.Time) ([]model.MessageBody, error)
	Sender() aggregator.Sender
}

// All is all the singleton check instances.
var All = []Check{
	Process,
	RTProcess,
	Container,
	RTContainer,
	Connections,
}

// GetSender is the default implementation to get the sender for each check
func GetSender(checkName string) aggregator.Sender {
	s, err := aggregator.GetSender(check.ID(checkName))
	if err != nil {
		_ = log.Error("No default sender available: ", err)
		// use LogSender when no sender instance is available
		s = processUtils.LogSender
	}
	// defer commit to send metrics after
	defer s.Commit()

	return s
}
