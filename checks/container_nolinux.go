// +build !linux

package checks

import (
	"github.com/StackVista/stackstate-process-agent/cmd/agent/features"
	"time"

	"github.com/StackVista/stackstate-agent/pkg/util/containers"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/util"
)

// Container is a singleton ContainerCheck.
var Container = &ContainerCheck{}

// ContainerCheck is a check that returns container metadata and stats.
type ContainerCheck struct {
	sysInfo *model.SystemInfo
	lastRun time.Time
}

// Init initializes a ContainerCheck instance.
func (c *ContainerCheck) Init(cfg *config.AgentConfig, info *model.SystemInfo) {
	c.sysInfo = info
}

// Name returns the name of the ProcessCheck.
func (c *ContainerCheck) Name() string { return "container" }

// Endpoint returns the endpoint where this check is submitted.
func (c *ContainerCheck) Endpoint() string { return "/api/v1/container" }

// RealTime indicates if this check only runs in real-time mode.
func (c *ContainerCheck) RealTime() bool { return false }

// Run runs the ContainerCheck to collect a list of running containers and the
// stats for each container.
func (c *ContainerCheck) Run(cfg *config.AgentConfig, features features.Features, groupID int32) ([]model.MessageBody, error) {

	return nil, nil
}

func fmtContainers(cfg *config.AgentConfig, ctrList []*containers.Container, lastRates map[string]util.ContainerRateMetrics, lastRun time.Time) []*model.Container {
	return make([]*model.Container, 0, len(ctrList))
}
