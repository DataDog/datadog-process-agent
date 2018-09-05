// +build !windows

package checks

import (
	"github.com/DataDog/gopsutil/process"
	"github.com/StackVista/stackstate-process-agent/config"
)

func getAllProcesses(*config.AgentConfig) (map[int32]*process.FilledProcess, error) {
	return process.AllProcesses()
}
