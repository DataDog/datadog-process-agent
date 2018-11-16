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
		return nil, nil
	}

	lines, err := util.ReadLines(configPath)
	if err != nil {
		return nil, fmt.Errorf("read error: %s", err)
	}

	return strings.NewReader(strings.Join(lines, "\n")), nil
}

func mergeYamlConfig(dc ddconfig.Config, agentConf *AgentConfig) (*AgentConfig, error) {
	apiKey := dc.GetString("api_key")

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

	en := dc.GetString(kEnabled)
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

	if enabled, err := isAffirmative(dc.GetString("LOGS_STDOUT")); err == nil {
		agentConf.LogToConsole = enabled
	}
	if enabled, err := isAffirmative(dc.GetString("LOG_TO_CONSOLE")); err == nil {
		agentConf.LogToConsole = enabled
	}

	if dc.IsSet(kLogFile) {
		agentConf.LogFile = dc.GetString(kLogFile)
	}

	if dc.IsSet(kIntervalsContainer) {
		agentConf.CheckIntervals["container"] = time.Duration(dc.GetInt(kIntervalsContainer)) * time.Second
	}
	if dc.IsSet(kIntervalsContainerRT) {
		agentConf.CheckIntervals["rtcontainer"] = time.Duration(dc.GetInt(kIntervalsContainerRT)) * time.Second
	}
	if dc.IsSet(kIntervalsProcess) {
		agentConf.CheckIntervals["process"] = time.Duration(dc.GetInt(kIntervalsProcess)) * time.Second
	}
	if dc.IsSet(kIntervalsProcessRT) {
		agentConf.CheckIntervals["rtprocess"] = time.Duration(dc.GetInt(kIntervalsProcessRT)) * time.Second
	}
	if dc.IsSet(kIntervalsConnections) {
		agentConf.CheckIntervals["connections"] = time.Duration(dc.GetInt(kIntervalsConnections)) * time.Second
	}

	if dc.IsSet(kBlacklistPatterns) {
		blackPat := dc.GetStringSlice(kBlacklistPatterns)
		blacklist := make([]*regexp.Regexp, 0, len(blackPat))
		for _, b := range blackPat {
			r, err := regexp.Compile(b)
			if err != nil {
				log.Warnf("Invalid blacklist pattern: %s", b)
			}
			blacklist = append(blacklist, r)
		}
		agentConf.Blacklist = blacklist
	}

	if dc.IsSet(kScrubArgs) {
		agentConf.Scrubber.Enabled = dc.GetBool(kScrubArgs)
	}

	if dc.IsSet(kCustomSensitiveWords) {
		csw := dc.GetString(kCustomSensitiveWords)
		agentConf.Scrubber.AddCustomSensitiveWords(strings.Split(csw, ","))
	}

	if dc.IsSet(kStripProcessArguments) {
		agentConf.Scrubber.StripAllArguments = dc.GetBool(kStripProcessArguments)
	}

	if dc.IsSet(kQueueSize) {
		agentConf.QueueSize = dc.GetInt(kQueueSize)
	}

	if dc.IsSet(kMaxProcFDs) {
		agentConf.MaxProcFDs = dc.GetInt(kMaxProcFDs)
	}

	if dc.IsSet(kMaxPerMessage) {
		if mpm := dc.GetInt(kMaxPerMessage); mpm <= maxMessageBatch {
			agentConf.MaxPerMessage = mpm
		} else {
			log.Warn("Overriding the configured item count per message limit because it exceeds maximum")
		}
	}

	if dc.IsSet(kDDAgentBin) {
		agentConf.DDAgentBin = dc.GetString(kDDAgentBin)
	}

	if dc.IsSet(kWinArgsRefreshInterval) {
		winAri := dc.GetInt(kWinArgsRefreshInterval)
		if winAri != 0 {
			agentConf.Windows.ArgsRefreshInterval = winAri
		}
	}

	if dc.IsSet(kWinAddNewArgs) {
		agentConf.Windows.AddNewArgs = dc.GetBool(kWinAddNewArgs)
	}

	if dc.IsSet(kAdditionalEndpoints) {
		additionalEndpoints := dc.GetStringMapStringSlice(kAdditionalEndpoints)
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
	}

	// Pull additional parameters from the global config file.
	if ok := dc.IsSet("log_level"); ok {
		agentConf.LogLevel = dc.GetString("log_level")
	}
	agentConf.StatsdPort = dc.GetInt("dogstatsd_port")
	agentConf.StatsdHost = dc.GetString("bind_host")
	agentConf.Transport = ddutil.CreateHTTPTransport()

	// Network related config
	if ok, _ := isAffirmative(dc.GetString(kNetworkTracingEnabled)); ok {
		agentConf.EnabledChecks = append(agentConf.EnabledChecks, "connections")
		agentConf.EnableNetworkTracing = true
	}

	if dc.IsSet(kNetworkUnixSocketPath) {
		agentConf.NetworkTracerSocketPath = dc.GetString(kNetworkUnixSocketPath)
	}

	if dc.IsSet(kNetworkLogFile) {
		agentConf.LogFile = dc.GetString(kNetworkLogFile)
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
