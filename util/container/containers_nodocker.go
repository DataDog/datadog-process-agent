// +build !docker

package container

import (
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/docker"
)

// GetDefaultListeners returns the default auto-discovery listeners, for use in container retrieval
func GetDefaultListeners() []config.Listeners {
	return nil
}

// GetContainers is the unique method that returns all containers on the host (or in the task)
// and that other agents can consume so that we don't have to convert all containers to the format.
func GetContainers() ([]*docker.Container, error) {
	return make([]*docker.Container, 0), docker.ErrNotImplemented
}
