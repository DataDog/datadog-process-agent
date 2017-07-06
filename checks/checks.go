package checks

import (
	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
)

type Check interface {
	Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error)
}
