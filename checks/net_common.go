package checks

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
)

// checks if the connection was in the previous collected connections
func keyMissingInLastConns(connKey string, lastConns map[string]common.ConnectionStats) (*common.ConnectionStats, bool) {
	lastConnection, ok := lastConns[connKey]

	if !ok {
		// Skipping any connection that didn't exist in the previous run.
		// This means short-lived connection (<2s) will never be captured.
		return nil, true
	}

	return &lastConnection, false
}
