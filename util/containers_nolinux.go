// +build !linux

package util

import (
	"github.com/DataDog/datadog-agent/pkg/util/containers"
)

// SetContainerSource is only implemented on Linux
func SetContainerSource(name string) {
	return
}

// GetContainers is only implemented on Linux
func GetContainers() ([]*containers.Container, error) {
	return nil, ErrNotImplemented
}
