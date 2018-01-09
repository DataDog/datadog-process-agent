package container

import (
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
		listeners = []config.Listeners{}
	}
}

// GetContainers is the unique method that returns all containers on the host (or in the task)
// and that other agents can consume so that we don't have to convert all containers to the format.
func GetContainers() ([]*docker.Container, error) {
	if listeners == nil {
		initContainerListeners()
	}

	var err error
	containers := make([]*docker.Container, 0)
	ctrListConfig := docker.ContainerListConfig{
		IncludeExited: false,
		FlagExcluded:  false,
	}

	for _, l := range listeners {
		switch l.Name {
		case "docker":
			du, err := docker.GetDockerUtil()
			if err != nil {
				log.Errorf("unable to connect to docker, passing this provider - %s", err)
				continue
			}
			ctrs, err := du.Containers(&ctrListConfig)
			if err != nil {
				log.Errorf("failed to get container list from docker - %s", err)
			}
			containers = append(containers, ctrs...)
		case "ecs":
			ctrs, err := ecs.GetContainers()
			if err != nil {
				log.Errorf("failed to get container list from ecs - %s", err)
			}
			containers = append(containers, ctrs...)
		default:
			log.Warnf("listener %s is not a known container provider, skipping it", l.Name)
		}
	}
	return containers, err
}
