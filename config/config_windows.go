// +build windows

package config

import (
	"path/filepath"

	"github.com/DataDog/datadog-agent/pkg/util/executable"
	"github.com/DataDog/datadog-agent/pkg/util/winutil"
)

var (
	defaultLogFilePath = "c:\\programdata\\datadog\\logs\\process-agent.log"

	// Agent 5
	defaultDDAgentPy    = "c:\\Program Files\\Datadog\\Datadog Agent\\embedded\\python.exe"
	defaultDDAgentPyEnv = "PYTHONPATH=c:\\Program Files\\Datadog\\Datadog Agent\\agent"

	// Agent 6
	defaultDDAgentBin = "c:\\Program Files\\Datadog\\Datadog Agent\\embedded\\agent.exe"
)

func init() {
	pd, err := winutil.GetProgramDataDir()
	if err == nil {
		defaultLogFilePath = filepath.Join(pd, "Datadog", "logs", "process-agent.log")
	}
	_here, err := executable.Folder()
	if err == nil {
		defaultDDAgentBin = filepath.Join(_here, "..", "..", "embedded", "agent.exe")
	}

}
