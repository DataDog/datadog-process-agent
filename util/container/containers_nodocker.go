// +build !docker

package container

import "github.com/DataDog/datadog-agent/pkg/util/docker"

// GetContainers is the unique method that returns all containers on the host (or in the task)
// and that other agents can consume so that we don't have to convert all containers to the format.
func GetContainers() ([]*docker.Container, error) {
	return *docker.Container{}, nil
}
