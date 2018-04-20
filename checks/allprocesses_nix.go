// +build !windows

package checks

import (
	"github.com/DataDog/gopsutil/process"
)

func getAllProcesses() (map[int32]*process.FilledProcess, error) {
	return process.AllProcesses()
}
