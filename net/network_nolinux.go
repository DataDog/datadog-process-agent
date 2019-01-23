// +build !linux

package net

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer"
	tracerCommon "github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
)

// RemoteNetTracerUtil is only implemented on linux
type RemoteNetTracerUtil struct{}

// SetNetworkTracerSocketPath is only implemented on linux
func SetNetworkTracerSocketPath(_ string) {
	// no-op
}

// GetRemoteNetworkTracerUtil is only implemented on linux
func GetRemoteNetworkTracerUtil() (*RemoteNetTracerUtil, error) {
	return &RemoteNetTracerUtil{}, nil
}

// GetConnections is only implemented on linux
func (r *RemoteNetTracerUtil) GetConnections() ([]tracer.ConnectionStats, error) {
	return nil, tracerCommon.ErrNotImplemented
}

// ShouldLogTracerUtilError is only implemented on linux
func ShouldLogTracerUtilError() bool {
	return false
}
