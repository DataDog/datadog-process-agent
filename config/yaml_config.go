package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	log "github.com/cihub/seelog"
	"gopkg.in/yaml.v2"

	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	ddutil "github.com/DataDog/datadog-agent/pkg/util"

	"github.com/StackVista/stackstate-process-agent/util"
)

// YamlAgentConfig is a structure used for marshaling the datadog.yaml configuration
// available in Agent versions >= 6
type YamlAgentConfig struct {
	APIKey string `yaml:"api_key"`
	Site   string `yaml:"site"`
	// Whether or not the process-agent should output logs to console
	LogToConsole bool `yaml:"log_to_console"`
	// Process-specific configuration
	Process struct {
		// A string indicate the enabled state of the Agent.
		// If "false" (the default) we will only collect containers.
		// If "true" we will collect containers and processes.
		// If "disabled" the agent will be disabled altogether and won't start.
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
			Connections       int `yaml:"connections"`
		} `yaml:"intervals"`
		// A list of regex patterns that will exclude a process if matched.
		BlacklistPatterns []string `yaml:"blacklist_patterns"`
		// Enable/Disable the DataScrubber to obfuscate process args
		// XXX: Using a bool pointer to differentiate between empty and set.
		ScrubArgs *bool `yaml:"scrub_args,omitempty"`
		// A custom word list to enhance the default one used by the DataScrubber
		CustomSensitiveWords []string `yaml:"custom_sensitive_words"`
		// Strips all process arguments
		StripProcessArguments bool `yaml:"strip_proc_arguments"`
		// How many check results to buffer in memory when POST fails. The default is usually fine.
		QueueSize int `yaml:"queue_size"`
		// The maximum number of file descriptors to open when collecting net connections.
		// Only change if you are running out of file descriptors from the Agent.
		MaxProcFDs int `yaml:"max_proc_fds"`
		// The maximum number of processes, connections or containers per message.
		// Only change if the defaults are causing issues.
		MaxPerMessage int `yaml:"max_per_message"`
		// Overrides the path to the Agent bin used for getting the hostname. The default is usually fine.
		DDAgentBin string `yaml:"dd_agent_bin"`
		// Overrides of the environment we pass to fetch the hostname. The default is usually fine.
		DDAgentEnv []string `yaml:"dd_agent_env"`
		// Optional additional pairs of endpoint_url => []apiKeys to submit to other locations.
		AdditionalEndpoints map[string][]string `yaml:"additional_endpoints"`
		// Windows-specific configuration goes in this section.
		Windows struct {
			// Sets windows process table refresh rate (in number of check runs)
			ArgsRefreshInterval int `yaml:"args_refresh_interval"`
			// Controls getting process arguments immediately when a new process is discovered
			// XXX: Using a bool pointer to differentiate between empty and set.
			AddNewArgs *bool `yaml:"add_new_args,omitempty"`
		} `yaml:"windows"`
	} `yaml:"process_config"`
	// Network-tracing specific configuration
	Network struct {
		// A string indicating the enabled state of the network tracer.
		NetworkTracingEnabled string `yaml:"network_tracing_enabled"`
		// A string indicating whether we use /proc to get the initial connections
		NetworkInitialConnectionFromProc string `yaml:"initial_connections_from_proc"`
		// The full path to the location of the unix socket where network traces will be accessed
		UnixSocketPath string `yaml:"nettracer_socket"`
		// The full path to the file where network-tracer logs will be written.
		LogFile string `yaml:"log_file"`
	} `yaml:"network_tracer_config"`
}

// NewYamlIfExists returns a new YamlAgentConfig if the given configPath is exists.
func NewYamlIfExists(configPath string) (*YamlAgentConfig, error) {
	var yamlConf YamlAgentConfig

	// Set default values for booleans otherwise it will default to false.
	defaultScrubArgs := true
	yamlConf.Process.ScrubArgs = &defaultScrubArgs
	defaultNewArgs := true
	yamlConf.Process.Windows.AddNewArgs = &defaultNewArgs

	if util.PathExists(configPath) {
		lines, err := util.ReadLines(configPath)
		if err != nil {
			return nil, fmt.Errorf("read error: %s", err)
		}
		if err = yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &yamlConf); err != nil {
			return nil, fmt.Errorf("parse error: %s", err)
		}
		return &yamlConf, nil
	}
	return nil, nil
}

func mergeYamlConfig(agentConf *AgentConfig, yc *YamlAgentConfig) (*AgentConfig, error) {
	agentConf.APIEndpoints[0].APIKey = yc.APIKey

	if enabled, err := isAffirmative(yc.Process.Enabled); enabled {
		agentConf.Enabled = true
		agentConf.EnabledChecks = processChecks
	} else if strings.ToLower(yc.Process.Enabled) == "disabled" {
		agentConf.Enabled = false
	} else if !enabled && err == nil {
		agentConf.Enabled = true
		agentConf.EnabledChecks = containerChecks
	}
	url, err := url.Parse(ddconfig.GetMainEndpoint("https://process.", "process_config.process_dd_url"))
	if err != nil {
		return nil, fmt.Errorf("error parsing process_dd_url: %s", err)
	}
	agentConf.APIEndpoints[0].Endpoint = url
	if yc.LogToConsole {
		agentConf.LogToConsole = true
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
	if yc.Process.Intervals.Connections != 0 {
		log.Infof("Overriding connections check interval to %ds", yc.Process.Intervals.Connections)
		agentConf.CheckIntervals["connections"] = time.Duration(yc.Process.Intervals.Connections) * time.Second
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

	// DataScrubber
	if yc.Process.ScrubArgs != nil {
		agentConf.Scrubber.Enabled = *yc.Process.ScrubArgs
	}
	agentConf.Scrubber.AddCustomSensitiveWords(yc.Process.CustomSensitiveWords)
	if yc.Process.StripProcessArguments {
		agentConf.Scrubber.StripAllArguments = yc.Process.StripProcessArguments
	}

	if yc.Process.QueueSize > 0 {
		agentConf.QueueSize = yc.Process.QueueSize
	}
	if yc.Process.MaxProcFDs > 0 {
		agentConf.MaxProcFDs = yc.Process.MaxProcFDs
	}
	if yc.Process.MaxPerMessage > 0 {
		if yc.Process.MaxPerMessage <= maxMessageBatch {
			agentConf.MaxPerMessage = yc.Process.MaxPerMessage
		} else {
			log.Warn("Overriding the configured item count per message limit because it exceeds maximum")
		}
	}
	agentConf.DDAgentBin = defaultDDAgentBin
	if yc.Process.DDAgentBin != "" {
		agentConf.DDAgentBin = yc.Process.DDAgentBin
	}

	if yc.Process.Windows.ArgsRefreshInterval != 0 {
		agentConf.Windows.ArgsRefreshInterval = yc.Process.Windows.ArgsRefreshInterval
	}
	if yc.Process.Windows.AddNewArgs != nil {
		agentConf.Windows.AddNewArgs = *yc.Process.Windows.AddNewArgs
	}

	for endpointURL, apiKeys := range yc.Process.AdditionalEndpoints {
		u, err := url.Parse(endpointURL)
		if err != nil {
			return nil, fmt.Errorf("invalid additional endpoint url '%s': %s", endpointURL, err)
		}
		for _, k := range apiKeys {
			agentConf.APIEndpoints = append(agentConf.APIEndpoints, APIEndpoint{
				APIKey:   k,
				Endpoint: u,
			})
		}
	}

	// Pull additional parameters from the global config file.
	agentConf.LogLevel = ddconfig.Datadog.GetString("log_level")
	agentConf.StatsdPort = ddconfig.Datadog.GetInt("dogstatsd_port")
	agentConf.Transport = ddutil.CreateHTTPTransport()

	return agentConf, nil
}

func mergeNetworkYamlConfig(agentConf *AgentConfig, networkConf *YamlAgentConfig) (*AgentConfig, error) {
	if enabled, _ := isAffirmative(networkConf.Network.NetworkTracingEnabled); enabled {
		agentConf.EnabledChecks = append(agentConf.EnabledChecks, "connections")
		agentConf.EnableNetworkTracing = enabled
	}
	if procEnabled, _ := isAffirmative(networkConf.Network.NetworkInitialConnectionFromProc); procEnabled {
		agentConf.NetworkInitialConnectionsFromProc = procEnabled
	}
	if socketPath := networkConf.Network.UnixSocketPath; socketPath != "" {
		agentConf.NetworkTracerSocketPath = socketPath
	}
	if networkConf.Network.LogFile != "" {
		agentConf.LogFile = networkConf.Network.LogFile
	}

	return agentConf, nil
}

// SetupDDAgentConfig initializes the datadog-agent config with a YAML file.
// This is required for configuration to be available for container listeners.
func SetupDDAgentConfig(configPath string) error {
	ddconfig.Datadog.AddConfigPath(configPath)
	// If they set a config file directly, let's try to honor that
	if strings.HasSuffix(configPath, ".yaml") {
		ddconfig.Datadog.SetConfigFile(configPath)
	}

	// load the configuration
	if err := ddconfig.Load(); err != nil {
		return fmt.Errorf("unable to load Datadog config file: %s", err)
	}

	return nil
}
