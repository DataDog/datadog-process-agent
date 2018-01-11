// +build docker

package container

import (
	"fmt"

	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/docker"
	"github.com/DataDog/datadog-agent/pkg/util/ecs"
)

var (
	listeners []config.Listeners
)

// Unmarshal the listeners once and store the result
func initContainerListeners() {
	if err := config.Datadog.UnmarshalKey("listeners", &listeners); err != nil {
		log.Errorf("unable to parse listeners from the datadog config - %s", err)
		// Default to all known listeners on parse failure
		listeners = []config.Listeners{
			{Name: "ecs"},
			{Name: "docker"},
		}
	}
}

// GetContainers is the unique method that returns all containers on the host (or in the task)
// and that other agents can consume so that we don't have to convert all containers to the format.
// NOTE: This is a modified copy of datadog-agent/pkg/util/container to prevent noisy logging
func GetContainers() ([]*docker.Container, []error) {
	if listeners == nil {
		initContainerListeners()
	}

	containers := make([]*docker.Container, 0)
	errs := make([]error, 0)
	ctrListConfig := docker.ContainerListConfig{
		IncludeExited: false,
		FlagExcluded:  false,
	}
	succeeded := false

	for _, l := range listeners {
		switch l.Name {
		case "docker":
			if du, err := docker.GetDockerUtil(); err == nil {
				if ctrs, err := du.Containers(&ctrListConfig); err == nil {
					succeeded = true
					containers = append(containers, ctrs...)
					continue
				}
				errs = append(errs, fmt.Errorf("failed to get container list from docker - %s", err))
			} else {
				errs = append(errs, fmt.Errorf("unable to connect to docker - %s", err))
			}
		case "ecs":
			if ctrs, err := ecs.GetContainers(); err != nil {
				errs = append(errs, fmt.Errorf("failed to get container list from ecs - %s", err))
			} else {
				succeeded = true
				containers = append(containers, ctrs...)
			}
		}
	}

	if succeeded { // Some container access method succeeded so drop errors from other access methods
		errs = []error{}
	}

	for _, e := range errs {
		log.Error(e)
	}

	return containers, errs
}
