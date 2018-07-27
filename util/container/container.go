// +build docker

// FIXME: remove, use util/containers.go instead

package container

import (
	"errors"
	"fmt"
	"strings"

	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/docker"
	"github.com/DataDog/datadog-agent/pkg/util/ecs"
)

var (
	listeners []config.Listeners
	// hasFatalError stores whether a listener has fatally error'd, to see if we should keep accessing its ctrList
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

// GetContainers is the unique method that returns all ctrList on the host (or in the task)
// and that other agents can consume so that we don't have to convert all ctrList to the format.
// NOTE: This is a modified copy of datadog-agent/pkg/util/container to prevent noisy logging
func GetContainers() ([]*containers.Container, error) {
	if listeners == nil {
		initContainerListeners()
	}

	var ctrList []*containers.Container
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
					ctrList = append(ctrList, ctrs...)
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
		case "ecs": // Fargate ctrList
			if ctrs, err := ecs.GetContainers(); err != nil {
				errs = append(errs, fmt.Errorf("failed to get container list from fargate - %s", err))
			} else {
				succeeded = true
				ctrList = append(ctrList, ctrs...)
			}
		}
	}

	if succeeded { // Some container access method succeeded so drop errors from other access methods
		return ctrList, nil
	}

	for _, e := range errs {
		log.Debug(e)
	}

	return ctrList, errors.New("failed to get ctrList from any source")
}
