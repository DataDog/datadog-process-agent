package config

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	log "github.com/cihub/seelog"
	"gopkg.in/yaml.v2"

	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	ddutil "github.com/DataDog/datadog-agent/pkg/util"

	"github.com/DataDog/datadog-process-agent/util"
)

// YamlAgentConfig is a structure used for marshaling the datadog.yaml configuration
// available in Agent versions >= 6
type YamlAgentConfig struct {
	Site string `yaml:"site"`
	// Process-specific configuration
	Process struct {
		// Overrides of the environment we pass to fetch the hostname. The default is usually fine.
		DDAgentEnv []string `yaml:"dd_agent_env"`
	} `yaml:"process_config"`
	// Network-tracing specific configuration
}

// NewYamlIfExists returns a new YamlAgentConfig if the given configPath is exists.
func NewYamlIfExists(configPath string) (*YamlAgentConfig, error) {
	var yamlConf YamlAgentConfig

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

// NewReaderIfExists returns a new io.Reader if the given configPath is exists.
func NewReaderIfExists(configPath string) (io.Reader, error) {
	if !util.PathExists(configPath) {
		return nil, fmt.Errorf("error path not found: %s", configPath)
	}

	lines, err := util.ReadLines(configPath)
	if err != nil {
		return nil, fmt.Errorf("read error: %s", err)
	}

	return strings.NewReader(strings.Join(lines, "\n")), nil
}

func mergeYamlConfig(agentConf *AgentConfig) (*AgentConfig, error) {
	apiKey := ddconfig.Datadog.GetString("api_key")
	if apiKey != "" {
		vals := strings.Split(apiKey, ",")
		for i := range vals {
			vals[i] = strings.TrimSpace(vals[i])
		}
		if len(agentConf.APIEndpoints) > 0 {
			agentConf.APIEndpoints[0].APIKey = vals[0]
		} else {
			agentConf.APIEndpoints = []APIEndpoint{{APIKey: vals[0]}}
		}
	}

	en := ddconfig.Datadog.GetString(kEnabled)
	if enabled, err := isAffirmative(en); enabled {
		agentConf.Enabled = true
		agentConf.EnabledChecks = processChecks
	} else if strings.ToLower(en) == "disabled" {
		agentConf.Enabled = false
	} else if !enabled && err == nil {
		agentConf.Enabled = true
		agentConf.EnabledChecks = containerChecks
	}

	url, err := url.Parse(ddconfig.GetMainEndpoint("https://process.", "process_config.process_dd_url"))
	if err != nil {
		return nil, fmt.Errorf("error parsing process_dd_url: %s", err)
	}
	if len(agentConf.APIEndpoints) > 0 {
		agentConf.APIEndpoints[0].Endpoint = url
	} else {
		agentConf.APIEndpoints = []APIEndpoint{{Endpoint: url}}
	}

	if enabled, err := isAffirmative(ddconfig.Datadog.GetString("LOGS_STDOUT")); err == nil {
		agentConf.LogToConsole = enabled
	}
	if enabled, err := isAffirmative(ddconfig.Datadog.GetString("LOG_TO_CONSOLE")); err == nil {
		agentConf.LogToConsole = enabled
	}

	agentConf.LogFile = ddconfig.Datadog.GetString(kLogFile)

	agentConf.CheckIntervals["container"] = time.Duration(ddconfig.Datadog.GetInt(kIntervalsContainer)) * time.Second
	agentConf.CheckIntervals["rtcontainer"] = time.Duration(ddconfig.Datadog.GetInt(kIntervalsContainerRT)) * time.Second
	agentConf.CheckIntervals["process"] = time.Duration(ddconfig.Datadog.GetInt(kIntervalsProcess)) * time.Second
	agentConf.CheckIntervals["rtprocess"] = time.Duration(ddconfig.Datadog.GetInt(kIntervalsProcessRT)) * time.Second
	agentConf.CheckIntervals["connections"] = time.Duration(ddconfig.Datadog.GetInt(kIntervalsConnections)) * time.Second

	blackPat := ddconfig.Datadog.GetStringSlice(kBlacklistPatterns)
	blacklist := make([]*regexp.Regexp, 0, len(blackPat))
	for _, b := range blackPat {
		r, err := regexp.Compile(b)
		if err != nil {
			log.Warnf("Invalid blacklist pattern: %s", b)
		}
		blacklist = append(blacklist, r)
	}
	agentConf.Blacklist = blacklist

	if ddconfig.Datadog.IsSet(kScrubArgs) {
		agentConf.Scrubber.Enabled = ddconfig.Datadog.GetBool(kScrubArgs)
	}

	csw := ddconfig.Datadog.GetString(kCustomSensitiveWords)
	agentConf.Scrubber.AddCustomSensitiveWords(strings.Split(csw, ","))

	agentConf.Scrubber.StripAllArguments = ddconfig.Datadog.GetBool(kStripProcessArguments)

	agentConf.QueueSize = ddconfig.Datadog.GetInt(kQueueSize)

	agentConf.MaxProcFDs = ddconfig.Datadog.GetInt(kMaxProcFDs)

	if mpm := ddconfig.Datadog.GetInt(kMaxPerMessage); mpm <= maxMessageBatch {
		agentConf.MaxPerMessage = mpm
	} else {
		log.Warn("Overriding the configured item count per message limit because it exceeds maximum")
	}

	agentConf.DDAgentBin = ddconfig.Datadog.GetString(kDDAgentBin)

	winAri := ddconfig.Datadog.GetInt(kWinArgsRefreshInterval)
	if winAri != 0 {
		agentConf.Windows.ArgsRefreshInterval = winAri
	}

	if ddconfig.Datadog.IsSet(kWinAddNewArgs) {
		agentConf.Windows.AddNewArgs = ddconfig.Datadog.GetBool(kWinAddNewArgs)
	}

	additionalEndpoints := ddconfig.Datadog.GetStringMapStringSlice(kAdditionalEndpoints)
	for endpointURL, apiKeys := range additionalEndpoints {
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
	agentConf.StatsdHost = ddconfig.Datadog.GetString("bind_host")
	agentConf.Transport = ddutil.CreateHTTPTransport()

	// Network related config
	if ok, _ := isAffirmative(ddconfig.Datadog.GetString(kNetworkTracingEnabled)); ok {
		agentConf.EnabledChecks = append(agentConf.EnabledChecks, "connections")
		agentConf.EnableNetworkTracing = true
	}

	if socketPath := ddconfig.Datadog.GetString(kNetworkUnixSocketPath); socketPath != "" {
		agentConf.NetworkTracerSocketPath = socketPath
	}

	if logFile := ddconfig.Datadog.GetString(kNetworkLogFile); logFile != "" {
		agentConf.LogFile = logFile
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
