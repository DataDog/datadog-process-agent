// +build docker

package container

import (
	"errors"
	"fmt"
	"strings"

	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/docker"
	"github.com/DataDog/datadog-agent/pkg/util/ecs"
)

var (
	listeners []config.Listeners
	// hasFatalError stores whether a listener has fatally error'd, to see if we should keep accessing its containers
	hasFatalError map[string]bool
)

// Unmarshal the listeners once and store the result
func initContainerListeners() {
	listeners = GetDefaultListeners()
	hasFatalError = make(map[string]bool)
}

// GetDefaultListeners returns the default auto-discovery listeners, for use in container retrieval
func GetDefaultListeners() []config.Listeners {
	l := []config.Listeners{{Name: "docker"}}
	// If we can detect that this is a fargate instance, lets add it as well
	if ecs.IsFargateInstance() {
		l = append(l, config.Listeners{Name: "ecs"})
	}
	return l
}

// GetContainers is the unique method that returns all containers on the host (or in the task)
// and that other agents can consume so that we don't have to convert all containers to the format.
// NOTE: This is a modified copy of datadog-agent/pkg/util/container to prevent noisy logging
func GetContainers() ([]*docker.Container, error) {
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
		if hasFatalError[l.Name] {
			continue
		}

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
				// If connecting permanently fails, we should skip further attempts (and its subsequent logging)
				if strings.HasPrefix(err.Error(), "permanent failure") {
					hasFatalError[l.Name] = true
				}
				errs = append(errs, fmt.Errorf("unable to connect to docker - %s", err))
			}
		case "ecs": // Fargate containers
			if ctrs, err := ecs.GetContainers(); err != nil {
				errs = append(errs, fmt.Errorf("failed to get container list from fargate - %s", err))
			} else {
				succeeded = true
				containers = append(containers, ctrs...)
			}
		}
	}

	if succeeded { // Some container access method succeeded so drop errors from other access methods
		return containers, nil
	}

	for _, e := range errs {
		log.Error(e)
	}

	return containers, errors.New("failed to get containers from any source")
}
