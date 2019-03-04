package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	ddutil "github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-process-agent/util"
	log "github.com/cihub/seelog"
	yaml "gopkg.in/yaml.v2"
)

const (
	ns = "process_config"
)

// NetworkAgentConfig is a structure used for marshaling the network-tracer.yaml configuration
// available in Agent versions >= 6
type NetworkAgentConfig struct { // Network-tracing specific configuration
	Network struct {
		// A string indicating the enabled state of the network tracer.
		NetworkTracingEnabled bool `yaml:"enabled"`
		// The full path to the location of the unix socket where network traces will be accessed
		UnixSocketPath string `yaml:"nettracer_socket"`
		// The full path to the file where network-tracer logs will be written.
		LogFile string `yaml:"log_file"`
		// Whether agent should disable collection for TCP connection type
		DisableTCP bool `yaml:"disable_tcp"`
		// Whether agent should disable collection for UDP connection type
		DisableUDP bool `yaml:"disable_udp"`
		// Whether agent should disable collection for IPv6 connection type
		DisableIPv6 bool `yaml:"disable_ipv6"`
		// The maximum number of connections per message.
		// Only change if the defaults are causing issues.
		MaxConnsPerMessage int `yaml:"max_conns_per_message"`
		// The maximum number of connections the tracer can track
		MaxTrackedConnections uint `yaml:"max_tracked_connections"`
		// Whether agent should expose profiling endpoints over the unix socket
		EnableDebugProfiling bool `yaml:"debug_profiling_enabled"`
	} `yaml:"network_tracer_config"`
}

// NetworkConfigIfExists returns a new NetworkAgentConfig if the given configPath is exists.
func NetworkConfigIfExists(path string) (*NetworkAgentConfig, error) {
	var yamlConf NetworkAgentConfig

	if util.PathExists(path) {
		lines, err := util.ReadLines(path)
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

func mergeNetworkYamlConfig(agentConf *AgentConfig, networkConf *NetworkAgentConfig) (*AgentConfig, error) {
	agentConf.DisableTCPTracing = networkConf.Network.DisableTCP
	agentConf.DisableUDPTracing = networkConf.Network.DisableUDP
	agentConf.DisableIPv6Tracing = networkConf.Network.DisableIPv6
	agentConf.EnableDebugProfiling = networkConf.Network.EnableDebugProfiling

	if networkConf.Network.NetworkTracingEnabled {
		agentConf.EnabledChecks = append(agentConf.EnabledChecks, "connections")
		agentConf.EnableNetworkTracing = true
	}
	if socketPath := networkConf.Network.UnixSocketPath; socketPath != "" {
		agentConf.NetworkTracerSocketPath = socketPath
	}
	if networkConf.Network.LogFile != "" {
		agentConf.LogFile = networkConf.Network.LogFile
	}

	if mcpm := networkConf.Network.MaxConnsPerMessage; mcpm > 0 {
		if mcpm <= maxConnsMessageBatch {
			agentConf.MaxConnsPerMessage = mcpm
		} else {
			log.Warn("Overriding the configured connections count per message limit because it exceeds maximum")
		}
	}

	if mtc := networkConf.Network.MaxTrackedConnections; mtc > 0 {
		if mtc <= maxMaxTrackedConnections {
			agentConf.MaxTrackedConnections = mtc
		} else {
			log.Warnf("Overriding the configured max tracked connections limit because it exceeds maximum 65536, got: %v", mtc)
		}
	}

	// Pull additional parameters from the global config file.
	agentConf.LogLevel = config.Datadog.GetString("log_level")
	agentConf.StatsdPort = config.Datadog.GetInt("dogstatsd_port")

	return agentConf, nil
}

func key(pieces ...string) string {
	return strings.Join(pieces, ".")
}

// Process-specific configuration
func (a *AgentConfig) loadProcessYamlConfig(path string) error {
	config.Datadog.AddConfigPath(path)
	if strings.HasSuffix(path, ".yaml") { // If they set a config file directly, let's try to honor that
		config.Datadog.SetConfigFile(path)
	}

	if err := config.Load(); err != nil {
		return err
	}

	URL, err := url.Parse(config.GetMainEndpoint("https://process.", key(ns, "process_dd_url")))
	if err != nil {
		return fmt.Errorf("error parsing process_dd_url: %s", err)
	}

	a.APIEndpoints[0].APIKey = config.Datadog.GetString("api_key")
	a.APIEndpoints[0].Endpoint = URL

	// A string indicate the enabled state of the Agent.
	// If "false" (the default) we will only collect containers.
	// If "true" we will collect containers and processes.
	// If "disabled" the agent will be disabled altogether and won't start.
	enabled := config.Datadog.GetString(key(ns, "enabled"))
	if ok, err := isAffirmative(enabled); ok {
		a.Enabled, a.EnabledChecks = true, processChecks
	} else if enabled == "disabled" {
		a.Enabled = false
	} else if !ok && err == nil {
		a.Enabled, a.EnabledChecks = true, containerChecks
	}

	// Whether or not the process-agent should output logs to console
	if config.Datadog.GetBool("log_to_console") {
		a.LogToConsole = true
	}
	// The full path to the file where process-agent logs will be written.
	if logFile := config.Datadog.GetString(key(ns, "log_file")); logFile != "" {
		a.LogFile = logFile
	}

	// The interval, in seconds, at which we will run each check. If you want consistent
	// behavior between real-time you may set the Container/ProcessRT intervals to 10.
	// Defaults to 10s for normal checks and 2s for others.
	a.setCheckInterval(ns, "container", "container")
	a.setCheckInterval(ns, "container_realtime", "rtcontainer")
	a.setCheckInterval(ns, "process", "process")
	a.setCheckInterval(ns, "process_realtime", "rtprocess")
	a.setCheckInterval(ns, "connections", "connections")

	// A list of regex patterns that will exclude a process if matched.
	for _, b := range config.Datadog.GetStringSlice(key(ns, "blacklist_patterns")) {
		r, err := regexp.Compile(b)
		if err != nil {
			log.Warnf("Ignoring invalid blacklist pattern: %s", b)
			continue
		}
		a.Blacklist = append(a.Blacklist, r)
	}

	// Enable/Disable the DataScrubber to obfuscate process args
	if scrubArgsKey := key(ns, "scrub_args"); config.Datadog.IsSet(scrubArgsKey) {
		a.Scrubber.Enabled = config.Datadog.GetBool(scrubArgsKey)
	}

	// A custom word list to enhance the default one used by the DataScrubber
	a.Scrubber.AddCustomSensitiveWords(config.Datadog.GetStringSlice(key(ns, "custom_sensitive_words")))

	// Strips all process arguments
	if config.Datadog.GetBool(key(ns, "strip_proc_arguments")) {
		a.Scrubber.StripAllArguments = true
	}

	// How many check results to buffer in memory when POST fails. The default is usually fine.
	if queueSize := config.Datadog.GetInt(key(ns, "queue_size")); queueSize > 0 {
		a.QueueSize = queueSize
	}

	// The maximum number of processes, or containers per message. Note: Only change if the defaults are causing issues.
	if maxPerMessage := config.Datadog.GetInt(key(ns, "max_per_message")); maxPerMessage > 0 {
		if maxPerMessage <= maxPerMessage {
			a.MaxPerMessage = maxPerMessage
		} else {
			log.Warn("Overriding the configured item count per message limit because it exceeds maximum")
		}
	}

	// Overrides the path to the Agent bin used for getting the hostname. The default is usually fine.
	a.DDAgentBin = defaultDDAgentBin
	if agentBin := config.Datadog.GetString(key(ns, "dd_agent_bin")); agentBin != "" {
		a.DDAgentBin = agentBin
	}

	// Windows: Sets windows process table refresh rate (in number of check runs)
	if argRefresh := config.Datadog.GetInt(key(ns, "windows", "args_refresh_interval")); argRefresh != 0 {
		a.Windows.ArgsRefreshInterval = argRefresh
	}

	// Windows: Controls getting process arguments immediately when a new process is discovered
	if addArgsKey := key(ns, "windows", "add_new_args"); config.Datadog.IsSet(addArgsKey) {
		a.Windows.AddNewArgs = config.Datadog.GetBool(addArgsKey)
	}

	// Optional additional pairs of endpoint_url => []apiKeys to submit to other locations.
	for endpointURL, apiKeys := range config.Datadog.GetStringMapStringSlice(key(ns, "additional_endpoints")) {
		u, err := URL.Parse(endpointURL)
		if err != nil {
			return fmt.Errorf("invalid additional endpoint url '%s': %s", endpointURL, err)
		}
		for _, k := range apiKeys {
			a.APIEndpoints = append(a.APIEndpoints, APIEndpoint{
				APIKey:   k,
				Endpoint: u,
			})
		}
	}

	// Pull additional parameters from the global config file.
	a.LogLevel = config.Datadog.GetString("log_level")
	a.StatsdPort = config.Datadog.GetInt("dogstatsd_port")
	a.Transport = ddutil.CreateHTTPTransport()

	return nil
}

func (a *AgentConfig) setCheckInterval(ns, check, checkKey string) {
	if interval := config.Datadog.GetInt(key(ns, "intervals", check)); interval != 0 {
		log.Infof("Overriding container check interval to %ds", interval)
		a.CheckIntervals[checkKey] = time.Duration(interval) * time.Second
	}
}
