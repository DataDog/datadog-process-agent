package checks

import (
	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
)

// Check is an interface for Agent checks that collect data. Each check returns
// a specific MessageBody type that will be published to the intake endpoint or
// processed in another way (e.g. printed for debugging).
type Check interface {
	Name() string
	Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error)
}
