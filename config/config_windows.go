// +build windows

package config

const (
	defaultLogFilePath = "c:\\programdata\\datadog\\logs\\process-agent.log"

	// Agent 5
	defaultDDAgentPy    = "c:\\Program Files\\Datadog\\Datadog Agent\\embedded\\python.exe"
	defaultDDAgentPyEnv = "PYTHONPATH=c:\\Program Files\\Datadog\\Datadog Agent\\agent"

	// Agent 6
	defaultDDAgentBin = "c:\\Program Files\\Datadog\\Datadog Agent\\embedded\\agent.exe"
)

// Process blacklist
var defaultBlacklistPatterns = []string{"cmd.exe", "conhost.exe", "DllHost.exe", "dwm.exe", "Explorer.EXE", "lsass.exe", "msdtc.exe", "SearchUI.exe", "sihost.exe", "smartscreen.exe", "svchost.exe", "taskhostw.exe", "tasklist.exe", "VBoxService.exe", "vim.exe", "wininit.exe", "winlogon.exe", "wlms.exe", "wmiprvse.exe", "sshd.exe"}
