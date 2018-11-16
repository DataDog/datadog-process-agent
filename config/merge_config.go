package config

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	ddutil "github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-process-agent/util"
	log "github.com/cihub/seelog"
	"github.com/go-ini/ini"
)

func mergeAPIKeys(apiKey string, agentConf *AgentConfig) {
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

// Uses viper config to retrieve both yaml and env variables
func mergeConfig(dc ddconfig.Config, agentConf *AgentConfig) error {
	apiKey := dc.GetString("api_key")

	if apiKey != "" {
		mergeAPIKeys(apiKey, agentConf)
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

	// TODO this should use the agent one
	getMainEndpoint := func(config ddconfig.Config, prefix string, ddURLKey string) (resolvedDDURL string) {
		if config.IsSet(ddURLKey) && config.GetString(ddURLKey) != "" {
			// value under ddURLKey takes precedence over 'site'
			resolvedDDURL = config.GetString(ddURLKey)
			if config.IsSet("site") {
				log.Infof("'site' and '%s' are both set in config: setting main endpoint to '%s': \"%s\"", ddURLKey, ddURLKey, config.GetString(ddURLKey))
			}
		} else if config.GetString("site") != "" {
			resolvedDDURL = prefix + strings.TrimSpace(config.GetString("site"))
		} else {
			resolvedDDURL = prefix + ddconfig.DefaultSite
		}
		return
	}

	url, err := url.Parse(getMainEndpoint(dc, "https://process.", "process_config.process_dd_url"))
	if err != nil {
		return fmt.Errorf("error parsing process_dd_url: %s", err)
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

	if dc.IsSet(kDDAgentPy) {
		agentConf.DDAgentPy = dc.GetString(kDDAgentPy)
	}

	if dc.IsSet(kDDAgentPyEnv) {
		agentConf.DDAgentPyEnv = strings.Split(dc.GetString(kDDAgentPyEnv), ",")
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
				return fmt.Errorf("invalid additional endpoint url '%s': %s", endpointURL, err)
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

	return nil
}

// mergeEnvironmentVariables applies overrides from environment variables to the process agent configuration
func mergeEnvironmentVariables(dc ddconfig.Config, c *AgentConfig) {
	var err error

	// Support API_KEY and DD_API_KEY but prefer DD_API_KEY.
	if v := os.Getenv("API_KEY"); v != "" {
		log.Info("overriding API key from env API_KEY value")
		mergeAPIKeys(v, c)
	}

	// Support LOG_LEVEL and DD_LOG_LEVEL but prefer DD_LOG_LEVEL
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}

	// TODO
	if c.proxy, err = proxyFromEnv(c.proxy); err != nil {
		log.Errorf("error parsing proxy settings, not using a proxy: %s", err)
		c.proxy = nil
	}

	if v := dc.GetString("dd_url"); v != "" {
		u, err := url.Parse(v)
		if err != nil {
			log.Warnf("DD_PROCESS_AGENT_URL/process_dd_url is invalid: %s", err)
		} else {
			if len(c.APIEndpoints) > 0 {
				c.APIEndpoints[0].Endpoint = u
			} else {
				c.APIEndpoints = []APIEndpoint{{Endpoint: u}}
			}
		}
		if site := os.Getenv("DD_SITE"); site != "" {
			log.Infof("Using 'process_dd_url' (%s) and ignoring 'site' (%s)", v, site)
		}
	}

	// Docker config
	c.CollectDockerNetwork, _ = isAffirmative(dc.GetString("COLLECT_DOCKER_NETWORK"))

	if v := dc.GetString("CONTAINER_BLACKLIST"); v != "" {
		c.ContainerBlacklist = strings.Split(v, ",")
	}
	if v := dc.GetString("CONTAINER_WHITELIST"); v != "" {
		c.ContainerWhitelist = strings.Split(v, ",")
	}
	if v := dc.GetString("CONTAINER_CACHE_DURATION"); v != "" {
		durationS, _ := strconv.Atoi(v)
		c.ContainerCacheDuration = time.Duration(durationS) * time.Second
	}

	// Used to override container source auto-detection.
	// "docker", "ecs_fargate", "kubelet", etc
	if v := dc.GetString("PROCESS_AGENT_CONTAINER_SOURCE"); v != "" {
		util.SetContainerSource(v)
	}

	if ok, _ := isAffirmative(dc.GetString("USE_LOCAL_NETWORK_TRACER")); ok {
		c.EnableLocalNetworkTracer = ok
	}
}

func mergeIniConfig(conf io.Reader, c *AgentConfig) error {
	agentIni, err := NewFromReaderIfExists(conf)
	if err != nil {
		return err
	}

	var section *ini.Section
	// Not considered as an error
	if agentIni != nil {
		if section, _ = agentIni.GetSection("Main"); section == nil {
			return nil
		}
	}

	a, err := agentIni.Get("Main", "api_key")

	if err != nil {
		return err
	}

	ak := strings.Split(a, ",")
	if len(c.APIEndpoints) == 0 {
		c.APIEndpoints = []APIEndpoint{{APIKey: ak[0]}}
	} else {
		c.APIEndpoints[0].APIKey = ak[0]
	}

	if len(ak) > 1 {
		for i := 1; i < len(ak); i++ {
			c.APIEndpoints = append(c.APIEndpoints, APIEndpoint{APIKey: ak[i]})
		}
	}

	c.LogLevel = strings.ToLower(agentIni.GetDefault("Main", "log_level", "INFO"))
	c.proxy, err = getProxySettings(section)
	if err != nil {
		log.Errorf("error parsing proxy settings, not using a proxy: %s", err)
	}

	v, _ := agentIni.Get("Main", "process_agent_enabled")
	if enabled, err := isAffirmative(v); enabled {
		c.Enabled = true
		c.EnabledChecks = processChecks
	} else if !enabled && err == nil { // Only want to disable the process agent if it's explicitly disabled
		c.Enabled = false
	}

	c.StatsdHost = agentIni.GetDefault("Main", "bind_host", c.StatsdHost)
	// non_local_traffic is a shorthand in dd-agent configuration that is
	// equivalent to setting `bind_host: 0.0.0.0`. Respect this flag
	// since it defaults to true in Docker and saves us a command-line param
	v, _ = agentIni.Get("Main", "non_local_traffic")
	if enabled, _ := isAffirmative(v); enabled {
		c.StatsdHost = "0.0.0.0"
	}
	c.StatsdPort = agentIni.GetIntDefault("Main", "dogstatsd_port", c.StatsdPort)

	// All process-agent specific config lives under [process.config] section.
	// NOTE: we truncate either endpoints or APIEndpoints if the lengths don't match
	ns := "process.config"
	endpoints := agentIni.GetStrArrayDefault(ns, "endpoint", ",", []string{defaultEndpoint})
	if len(endpoints) < len(c.APIEndpoints) {
		log.Warnf("found %d api keys and %d endpoints", len(c.APIEndpoints), len(endpoints))
		c.APIEndpoints = c.APIEndpoints[:len(endpoints)]
	} else if len(endpoints) > len(c.APIEndpoints) {
		log.Warnf("found %d api keys and %d endpoints", len(c.APIEndpoints), len(endpoints))
		endpoints = endpoints[:len(c.APIEndpoints)]
	}
	for i, e := range endpoints {
		u, err := url.Parse(e)
		if err != nil {
			return fmt.Errorf("invalid endpoint URL: %s", err)
		}
		c.APIEndpoints[i].Endpoint = u
	}

	c.QueueSize = agentIni.GetIntDefault(ns, "queue_size", c.QueueSize)
	c.MaxProcFDs = agentIni.GetIntDefault(ns, "max_proc_fds", c.MaxProcFDs)
	c.AllowRealTime = agentIni.GetBool(ns, "allow_real_time", c.AllowRealTime)
	c.LogFile = agentIni.GetDefault(ns, "log_file", c.LogFile)
	c.DDAgentPy = agentIni.GetDefault(ns, "dd_agent_py", c.DDAgentPy)
	c.DDAgentPyEnv = agentIni.GetStrArrayDefault(ns, "dd_agent_py_env", ",", c.DDAgentPyEnv)

	blacklistPats := agentIni.GetStrArrayDefault(ns, "blacklist", ",", []string{})
	blacklist := make([]*regexp.Regexp, 0, len(blacklistPats))
	for _, b := range blacklistPats {
		r, err := regexp.Compile(b)
		if err == nil {
			blacklist = append(blacklist, r)
		}
	}
	c.Blacklist = blacklist

	// DataScrubber
	c.Scrubber.Enabled = agentIni.GetBool(ns, "scrub_args", true)
	customSensitiveWords := agentIni.GetStrArrayDefault(ns, "custom_sensitive_words", ",", []string{})
	c.Scrubber.AddCustomSensitiveWords(customSensitiveWords)
	c.Scrubber.StripAllArguments = agentIni.GetBool(ns, "strip_proc_arguments", false)

	batchSize := agentIni.GetIntDefault(ns, "proc_limit", c.MaxPerMessage)
	if batchSize <= maxMessageBatch {
		c.MaxPerMessage = batchSize
	} else {
		log.Warn("Overriding the configured item count per message limit because it exceeds maximum")
		c.MaxPerMessage = maxMessageBatch
	}

	// Checks intervals can be overridden by configuration.
	for checkName, defaultInterval := range c.CheckIntervals {
		key := fmt.Sprintf("%s_interval", checkName)
		interval := agentIni.GetDurationDefault(ns, key, time.Second, defaultInterval)
		if interval != defaultInterval {
			log.Infof("Overriding check interval for %s to %s", checkName, interval)
			c.CheckIntervals[checkName] = interval
		}
	}

	// Docker config
	c.CollectDockerNetwork = agentIni.GetBool(ns, "collect_docker_network", c.CollectDockerNetwork)
	c.ContainerBlacklist = agentIni.GetStrArrayDefault(ns, "container_blacklist", ",", c.ContainerBlacklist)
	c.ContainerWhitelist = agentIni.GetStrArrayDefault(ns, "container_whitelist", ",", c.ContainerWhitelist)
	c.ContainerCacheDuration = agentIni.GetDurationDefault(ns, "container_cache_duration", time.Second, 30*time.Second)

	// windows args config
	c.Windows.ArgsRefreshInterval = agentIni.GetIntDefault(ns, "windows_args_refresh_interval", c.Windows.ArgsRefreshInterval)
	c.Windows.AddNewArgs = agentIni.GetBool(ns, "windows_add_new_args", true)

	return nil
}
