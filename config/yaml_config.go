package config

import (
	"fmt"
	"net/url"
	"regexp"
	"time"

	log "github.com/cihub/seelog"
)

// YamlAgentConfig is a sturcutre used for marshaling the datadog.yaml configuratio
// available in Agent versions >= 6
type YamlAgentConfig struct {
	APIKey       string `yaml:"api_key"`
	ProcessDDURL string `yaml:"process_dd_url"`
	Process      struct {
		// A string boolean indicating if the Agent is enabled.
		Enabled string `yaml:"enabled"`
		// The full path to the file where process-agent logs will be written.
		LogFile string `yaml:"log_file"`
		// The interval, in seconds, at which we will run each check. If you want consistent
		// behavior between real-time you may set the Container/ProcessRT intervals to 10.
		// Defaults to 10s for normal checks and 2s for others.
		Intervals struct {
			Container         int `yaml:"container"`
			ContainerRealTime int `yaml:"container_realtime"`
			Process           int `yaml:"process"`
			ProcessRealTime   int `yaml:"process_realtime"`
		} `yaml:"intervals"`
		// A list of regex patterns that will exclude a process if matched.
		BlacklistPatterns []string `yaml:"blacklist_patterns"`
		// How many check results to buffer in memory when POST fails. The default is usually fine.
		QueueSize int `yaml:"queue_size"`
		// The maximum number of file descriptors to open when collecting net connections.
		// Only change if you are running out of file descriptors from the Agent.
		MaxProcFDs int `yaml:"max_proc_fds"`
		// The maximum number of processes or containers per message.
		// Only change if the defaults are causing issues.
		MaxPerMessage int `yaml:"max_per_message"`
		// Overrides the path to the Agent bin used for getting the hostname. The default is usually fine.
		DDAgentBin string `yaml:"dd_agent_bin"`
		// Overrides of the environment we pass to fetch the hostname. The default is usually fine.
		DDAgentEnv []string `yaml:"dd_agent_env"`
	} `yaml:"process_config"`
}

func mergeYamlConfig(agentConf *AgentConfig, yc *YamlAgentConfig) (*AgentConfig, error) {
	agentConf.APIKey = yc.APIKey
	if yc.Process.Enabled == "true" {
		agentConf.Enabled = true
	} else if yc.Process.Enabled == "false" {
		agentConf.Enabled = false
	}
	if yc.ProcessDDURL != "" {
		u, err := url.Parse(yc.ProcessDDURL)
		if err != nil {
			return nil, fmt.Errorf("invalid process_dd_url: %s", err)
		}
		agentConf.APIEndpoint = u
	}
	if yc.Process.LogFile != "" {
		agentConf.LogFile = yc.Process.LogFile
	}
	if yc.Process.Intervals.Container != 0 {
		log.Infof("Overriding container check interval to %ds", yc.Process.Intervals.Container)
		agentConf.CheckIntervals["container"] = time.Duration(yc.Process.Intervals.Container) * time.Second
	}
	if yc.Process.Intervals.ContainerRealTime != 0 {
		log.Infof("Overriding real-time container check interval to %ds", yc.Process.Intervals.ContainerRealTime)
		agentConf.CheckIntervals["rtcontainer"] = time.Duration(yc.Process.Intervals.ContainerRealTime) * time.Second
	}
	if yc.Process.Intervals.Process != 0 {
		log.Infof("Overriding process check interval to %ds", yc.Process.Intervals.Process)
		agentConf.CheckIntervals["process"] = time.Duration(yc.Process.Intervals.Process) * time.Second
	}
	if yc.Process.Intervals.ProcessRealTime != 0 {
		log.Infof("Overriding real-time process check interval to %ds", yc.Process.Intervals.ProcessRealTime)
		agentConf.CheckIntervals["rtprocess"] = time.Duration(yc.Process.Intervals.Process) * time.Second
	}
	blacklist := make([]*regexp.Regexp, 0, len(yc.Process.BlacklistPatterns))
	for _, b := range yc.Process.BlacklistPatterns {
		r, err := regexp.Compile(b)
		if err != nil {
			log.Warnf("Invalid blacklist pattern: %s", b)
		}
		blacklist = append(blacklist, r)
	}
	agentConf.Blacklist = blacklist
	if yc.Process.QueueSize > 0 {
		agentConf.QueueSize = yc.Process.QueueSize
	}
	if yc.Process.MaxProcFDs > 0 {
		agentConf.MaxProcFDs = yc.Process.MaxProcFDs
	}
	if yc.Process.MaxPerMessage > 0 {
		if yc.Process.MaxPerMessage <= maxProcLimit {
			agentConf.ProcLimit = yc.Process.MaxPerMessage
		} else {
			log.Warn("Overriding the configured process limit because it exceeds maximum")
		}
	}
	agentConf.DDAgentBin = "/opt/datadog-agent/bin/agent/agent"
	if yc.Process.DDAgentBin != "" {
		agentConf.DDAgentBin = yc.Process.DDAgentBin
	}
	return agentConf, nil
}
