// +build !windows

package config

const (
	defaultLogFilePath = "/var/log/datadog/process-agent.log"

	// Agent 5
	defaultDDAgentPy    = "/opt/datadog-agent/embedded/bin/python"
	defaultDDAgentPyEnv = "PYTHONPATH=/opt/datadog-agent/agent"

	// Agent 6
	defaultDDAgentBin = "/opt/datadog-agent/bin/agent/agent"
)
