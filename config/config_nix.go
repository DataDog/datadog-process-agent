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

// Process blacklist
var defaultBlacklistPatterns = []string{"stress", "^-bash", "^su$", "^/bin/bash", "^/lib/systemd/", "^pickup", "^/sbin/", "^qmgr", "^sshd:", "^/usr/bin/bash", "^/usr/bin/dbus-daemon", "^/usr/bin/vi(?:m|m.basic)?$", "^/usr/bin/tail", "^/usr/lib/systemd/", "^/usr/sbin/", "^\\(sd-pam\\)"}
