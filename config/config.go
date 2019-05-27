//go:generate goderive .

package config

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/StackVista/stackstate-process-agent/util"

	ddconfig "github.com/StackVista/stackstate-agent/pkg/config"
	ecsutil "github.com/StackVista/stackstate-agent/pkg/util/ecs"

	log "github.com/cihub/seelog"
	"github.com/go-ini/ini"
)

var (
	// defaultProxyPort is the default port used for proxies.
	// This mirrors the configuration for the infrastructure agent.
	defaultProxyPort = 3128

	// defaultNetworkTracerSocketPath is the default unix socket path to be used for connecting to the network tracer
	defaultNetworkTracerSocketPath = "/opt/datadog-agent/run/nettracer.sock"
	// defaultNetworkLogFilePath is the default logging file for the network tracer
	defaultNetworkLogFilePath = "/var/log/datadog/network-tracer.log"

	processChecks   = []string{"process", "rtprocess"}
	containerChecks = []string{"container", "rtcontainer"}

	// List of known Kubernetes images that we want to exclude by default.
	defaultKubeBlacklist = []string{
		"image:gcr.io/google_containers/pause.*",
		"image:openshift/origin-pod",
	}
)

type proxyFunc func(*http.Request) (*url.URL, error)

// WindowsConfig stores all windows-specific configuration for the process-agent.
type WindowsConfig struct {
	// Number of checks runs between refreshes of command-line arguments
	ArgsRefreshInterval int
	// Controls getting process arguments immediately when a new process is discovered
	AddNewArgs bool
}

// APIEndpoint is a single endpoint where process data will be submitted.
type APIEndpoint struct {
	APIKey   string
	Endpoint *url.URL
}

// AgentConfig is the global config for the process-agent. This information
// is sourced from config files and the environment variables.
type AgentConfig struct {
	Enabled       bool
	HostName      string
	APIEndpoints  []APIEndpoint
	LogFile       string
	LogLevel      string
	LogToConsole  bool
	QueueSize     int
	Blacklist     []*regexp.Regexp
	Scrubber      *DataScrubber
	MaxProcFDs    int
	MaxPerMessage int
	AllowRealTime bool
	Transport     *http.Transport `json:"-"`
	Logger        *LoggerConfig
	DDAgentPy     string
	DDAgentBin    string
	DDAgentPyEnv  []string
	StatsdHost    string
	StatsdPort    int

	// Top resource using process inclusion amounts
	AmountTopCPUPercentageUsage int
	CPUPercentageUsageThreshold int
	AmountTopIOReadUsage        int
	AmountTopIOWriteUsage       int
	AmountTopMemoryUsage        int
	MemoryUsageThreshold        int

	// Network collection configuration
	EnableNetworkTracing              bool
	EnableLocalNetworkTracer          bool // To have the network tracer embedded in the process-agent
	NetworkInitialConnectionsFromProc bool
	NetworkTracerSocketPath           string
	NetworkTracerLogFile              string

	// Check config
	EnabledChecks  []string
	CheckIntervals map[string]time.Duration

	// Containers
	ContainerBlacklist     []string
	ContainerWhitelist     []string
	CollectDockerNetwork   bool
	ContainerCacheDuration time.Duration

	// Internal store of a proxy used for generating the Transport
	proxy proxyFunc

	// Windows-specific config
	Windows WindowsConfig
}

// CheckIsEnabled returns a bool indicating if the given check name is enabled.
func (a AgentConfig) CheckIsEnabled(checkName string) bool {
	return util.StringInSlice(a.EnabledChecks, checkName)
}

// CheckInterval returns the interval for the given check name, defaulting to 10s if not found.
func (a AgentConfig) CheckInterval(checkName string) time.Duration {
	d, ok := a.CheckIntervals[checkName]
	if !ok {
		log.Errorf("missing check interval for '%s', you must set a default", checkName)
		d = 10 * time.Second
	}
	return d
}

const (
	defaultEndpoint = "https://process.datadoghq.com"
	maxMessageBatch = 100
)

// NewDefaultTransport provides a http transport configuration with sane default timeouts
func NewDefaultTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:    5,
		IdleConnTimeout: 90 * time.Second,
		Dial: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// NewDefaultAgentConfig returns an AgentConfig with defaults initialized
func NewDefaultAgentConfig() *AgentConfig {
	u, err := url.Parse(defaultEndpoint)
	if err != nil {
		// This is a hardcoded URL so parsing it should not fail
		panic(err)
	}

	// Note: This only considers container sources that are already setup. It's possible that container sources may
	//       need a few minutes to be ready.
	_, err = util.GetContainers()
	canAccessContainers := err == nil

	ac := &AgentConfig{
		Enabled:       canAccessContainers, // We'll always run inside of a container.
		APIEndpoints:  []APIEndpoint{{Endpoint: u}},
		LogFile:       defaultLogFilePath,
		LogLevel:      "info",
		LogToConsole:  false,
		QueueSize:     20,
		MaxProcFDs:    200,
		MaxPerMessage: 2000,
		AllowRealTime: true,
		HostName:      "",
		Transport:     NewDefaultTransport(),

		// Statsd for internal instrumentation
		StatsdHost: "127.0.0.1",
		StatsdPort: 8125,

		Blacklist: deriveFmapConstructRegex(constructRegex, defaultBlacklistPatterns),

		// Top resource using process inclusion amounts
		AmountTopCPUPercentageUsage: 0,
		AmountTopIOReadUsage:        0,
		AmountTopIOWriteUsage:       0,
		AmountTopMemoryUsage:        0,

		// Path and environment for the dd-agent embedded python
		DDAgentPy:    defaultDDAgentPy,
		DDAgentPyEnv: []string{defaultDDAgentPyEnv},

		// Network collection configuration
		EnableNetworkTracing:              false,
		EnableLocalNetworkTracer:          true,
		NetworkInitialConnectionsFromProc: true,
		NetworkTracerSocketPath:           defaultNetworkTracerSocketPath,
		NetworkTracerLogFile:              defaultNetworkLogFilePath,

		// Check config
		EnabledChecks: containerChecks,
		CheckIntervals: map[string]time.Duration{
			"process":     10 * time.Second,
			"rtprocess":   2 * time.Second,
			"container":   10 * time.Second,
			"rtcontainer": 2 * time.Second,
			"connections": 10 * time.Second,
		},

		// Docker
		ContainerCacheDuration: 10 * time.Second,
		CollectDockerNetwork:   true,

		// DataScrubber to hide command line sensitive words
		Scrubber: NewDefaultDataScrubber(),

		// Windows process config
		Windows: WindowsConfig{
			ArgsRefreshInterval: 15, // with default 20s check interval we refresh every 5m
			AddNewArgs:          true,
		},
	}

	// Set default values for proc/sys paths if unset.
	// Don't set this is /host is not mounted to use context within container.
	// Generally only applicable for container-only cases like Fargate.
	if ddconfig.IsContainerized() && util.PathExists("/host") {
		if v := os.Getenv("HOST_PROC"); v == "" {
			os.Setenv("HOST_PROC", "/host/proc")
		}
		if v := os.Getenv("HOST_SYS"); v == "" {
			os.Setenv("HOST_SYS", "/host/sys")
		}
	}

	if isRunningInKubernetes() {
		ac.ContainerBlacklist = defaultKubeBlacklist
	}

	return ac
}

func isRunningInKubernetes() bool {
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// NewAgentConfig returns an AgentConfig using a configuration file. It can be nil
// if there is no file available. In this case we'll configure only via environment.
func NewAgentConfig(agentIni *File, agentYaml *YamlAgentConfig, networkYaml *YamlAgentConfig) (*AgentConfig, error) {
	var err error
	cfg := NewDefaultAgentConfig()

	var ns string
	var section *ini.Section
	if agentIni != nil {
		section, _ = agentIni.GetSection("Main")
	}

	// Pull from the ini Agent config by default.
	if section != nil {
		a, err := agentIni.Get("Main", "api_key")
		if err != nil {
			return nil, err
		}
		ak := strings.Split(a, ",")
		cfg.APIEndpoints[0].APIKey = ak[0]
		if len(ak) > 1 {
			for i := 1; i < len(ak); i++ {
				cfg.APIEndpoints = append(cfg.APIEndpoints, APIEndpoint{APIKey: ak[i]})
			}
		}

		cfg.LogLevel = strings.ToLower(agentIni.GetDefault("Main", "log_level", "INFO"))
		cfg.proxy, err = getProxySettings(section)
		if err != nil {
			log.Errorf("error parsing proxy settings, not using a proxy: %s", err)
		}

		v, _ := agentIni.Get("Main", "process_agent_enabled")
		if enabled, err := isAffirmative(v); enabled {
			cfg.Enabled = true
			cfg.EnabledChecks = processChecks
		} else if !enabled && err == nil { // Only want to disable the process agent if it's explicitly disabled
			cfg.Enabled = false
		}

		cfg.StatsdHost = agentIni.GetDefault("Main", "bind_host", cfg.StatsdHost)
		// non_local_traffic is a shorthand in dd-agent configuration that is
		// equivalent to setting `bind_host: 0.0.0.0`. Respect this flag
		// since it defaults to true in Docker and saves us a command-line param
		v, _ = agentIni.Get("Main", "non_local_traffic")
		if enabled, _ := isAffirmative(v); enabled {
			cfg.StatsdHost = "0.0.0.0"
		}
		cfg.StatsdPort = agentIni.GetIntDefault("Main", "dogstatsd_port", cfg.StatsdPort)

		// All process-agent specific config lives under [process.config] section.
		// NOTE: we truncate either endpoints or APIEndpoints if the lengths don't match
		ns = "process.config"
		endpoints := agentIni.GetStrArrayDefault(ns, "endpoint", ",", []string{defaultEndpoint})
		if len(endpoints) < len(cfg.APIEndpoints) {
			log.Warnf("found %d api keys and %d endpoints", len(cfg.APIEndpoints), len(endpoints))
			cfg.APIEndpoints = cfg.APIEndpoints[:len(endpoints)]
		} else if len(endpoints) > len(cfg.APIEndpoints) {
			log.Warnf("found %d api keys and %d endpoints", len(cfg.APIEndpoints), len(endpoints))
			endpoints = endpoints[:len(cfg.APIEndpoints)]
		}
		for i, e := range endpoints {
			u, err := url.Parse(e)
			if err != nil {
				return nil, fmt.Errorf("invalid endpoint URL: %s", err)
			}
			cfg.APIEndpoints[i].Endpoint = u
		}

		cfg.QueueSize = agentIni.GetIntDefault(ns, "queue_size", cfg.QueueSize)
		cfg.MaxProcFDs = agentIni.GetIntDefault(ns, "max_proc_fds", cfg.MaxProcFDs)
		cfg.AllowRealTime = agentIni.GetBool(ns, "allow_real_time", cfg.AllowRealTime)
		cfg.LogFile = agentIni.GetDefault(ns, "log_file", cfg.LogFile)
		cfg.DDAgentPy = agentIni.GetDefault(ns, "dd_agent_py", cfg.DDAgentPy)
		cfg.DDAgentPyEnv = agentIni.GetStrArrayDefault(ns, "dd_agent_py_env", ",", cfg.DDAgentPyEnv)

		blacklistPats := agentIni.GetStrArrayDefault(ns, "blacklist", ",", []string{})
		blacklist := make([]*regexp.Regexp, 0, len(blacklistPats))
		for _, b := range blacklistPats {
			r, err := regexp.Compile(b)
			if err == nil {
				blacklist = append(blacklist, r)
			}
		}
		cfg.Blacklist = blacklist

		// DataScrubber
		cfg.Scrubber.Enabled = agentIni.GetBool(ns, "scrub_args", true)
		customSensitiveWords := agentIni.GetStrArrayDefault(ns, "custom_sensitive_words", ",", []string{})
		cfg.Scrubber.AddCustomSensitiveWords(customSensitiveWords)
		cfg.Scrubber.StripAllArguments = agentIni.GetBool(ns, "strip_proc_arguments", false)

		batchSize := agentIni.GetIntDefault(ns, "proc_limit", cfg.MaxPerMessage)
		if batchSize <= maxMessageBatch {
			cfg.MaxPerMessage = batchSize
		} else {
			log.Warn("Overriding the configured item count per message limit because it exceeds maximum")
			cfg.MaxPerMessage = maxMessageBatch
		}

		// Checks intervals can be overridden by configuration.
		for checkName, defaultInterval := range cfg.CheckIntervals {
			key := fmt.Sprintf("%s_interval", checkName)
			interval := agentIni.GetDurationDefault(ns, key, time.Second, defaultInterval)
			if interval != defaultInterval {
				log.Infof("Overriding check interval for %s to %s", checkName, interval)
				cfg.CheckIntervals[checkName] = interval
			}
		}

		// Docker config
		cfg.CollectDockerNetwork = agentIni.GetBool(ns, "collect_docker_network", cfg.CollectDockerNetwork)
		cfg.ContainerBlacklist = agentIni.GetStrArrayDefault(ns, "container_blacklist", ",", cfg.ContainerBlacklist)
		cfg.ContainerWhitelist = agentIni.GetStrArrayDefault(ns, "container_whitelist", ",", cfg.ContainerWhitelist)
		cfg.ContainerCacheDuration = agentIni.GetDurationDefault(ns, "container_cache_duration", time.Second, 30*time.Second)

		// windows args config
		cfg.Windows.ArgsRefreshInterval = agentIni.GetIntDefault(ns, "windows_args_refresh_interval", cfg.Windows.ArgsRefreshInterval)
		cfg.Windows.AddNewArgs = agentIni.GetBool(ns, "windows_add_new_args", true)
	}

	// For Agents >= 6 we will have a YAML config file to use.
	if agentYaml != nil {
		if cfg, err = mergeYamlConfig(cfg, agentYaml); err != nil {
			return nil, err
		}
		if cfg, err = mergeNetworkYamlConfig(cfg, agentYaml); err != nil {
			return nil, err
		}
	}

	if networkYaml != nil {
		if cfg, err = mergeNetworkYamlConfig(cfg, networkYaml); err != nil {
			return nil, err
		}
	}

	// Use environment to override any additional config.
	cfg = mergeEnvironmentVariables(cfg)

	// Python-style log level has WARNING vs WARN
	if strings.ToLower(cfg.LogLevel) == "warning" {
		cfg.LogLevel = "warn"
	}

	// (Re)configure the logging from our configuration
	if err := NewLoggerLevel(cfg.LogLevel, cfg.LogFile, cfg.LogToConsole); err != nil {
		return nil, err
	}

	if cfg.HostName == "" {
		if ecsutil.IsFargateInstance() {
			// Fargate tasks should have no concept of host names, so we're using the task ARN.
			if taskMeta, err := ecsutil.GetTaskMetadata(); err == nil {
				cfg.HostName = fmt.Sprintf("fargate_task:%s", taskMeta.TaskARN)
			} else {
				log.Errorf("Failed to retrieve Fargate task metadata: %s", err)
			}
		} else if hostname, err := getHostname(cfg.DDAgentPy, cfg.DDAgentBin, cfg.DDAgentPyEnv); err == nil {
			cfg.HostName = hostname
		}
	}

	if cfg.proxy != nil {
		cfg.Transport.Proxy = cfg.proxy
	}

	// sanity check. This element is used with the modulo operator (%), so it can't be zero.
	// if it is, log the error, and assume the config was attempting to disable
	if cfg.Windows.ArgsRefreshInterval == 0 {
		log.Warnf("invalid configuration: windows_collect_skip_new_args was set to 0.  Disabling argument collection")
		cfg.Windows.ArgsRefreshInterval = -1
	}

	return cfg, nil
}

// NewNetworkAgentConfig returns a network-tracer specific AgentConfig using a configuration file. It can be nil
// if there is no file available. In this case we'll configure only via environment.
func NewNetworkAgentConfig(networkYaml *YamlAgentConfig) (*AgentConfig, error) {
	cfg := NewDefaultAgentConfig()
	var err error

	if networkYaml != nil {
		if cfg, err = mergeNetworkYamlConfig(cfg, networkYaml); err != nil {
			return nil, fmt.Errorf("failed to parse config: %s", err)
		}
	}

	cfg = mergeEnvironmentVariables(cfg)

	// (Re)configure the logging from our configuration, with the network tracer logfile
	if err := NewLoggerLevel(cfg.LogLevel, cfg.NetworkTracerLogFile, cfg.LogToConsole); err != nil {
		return nil, fmt.Errorf("failed to setup network-tracer logger: %s", err)
	}

	return cfg, nil
}

// mergeEnvironmentVariables applies overrides from environment variables to the process agent configuration
func mergeEnvironmentVariables(c *AgentConfig) *AgentConfig {
	var err error
	if enabled, err := isAffirmative(os.Getenv("DD_PROCESS_AGENT_ENABLED")); enabled {
		c.Enabled = true
		c.EnabledChecks = processChecks
	} else if !enabled && err == nil {
		c.Enabled = false
	}

	if v := os.Getenv("DD_HOSTNAME"); v != "" {
		log.Info("overriding hostname from env DD_HOSTNAME value")
		c.HostName = v
	}

	// Support API_KEY and DD_API_KEY but prefer DD_API_KEY.
	var apiKey string
	if v := os.Getenv("API_KEY"); v != "" {
		apiKey = v
		log.Info("overriding API key from env API_KEY value")
	}
	if v := os.Getenv("DD_API_KEY"); v != "" {
		apiKey = v
		log.Infof("overriding API key from env DD_API_KEY value %s", apiKey)
	}
	if apiKey != "" {
		vals := strings.Split(apiKey, ",")
		for i := range vals {
			vals[i] = strings.TrimSpace(vals[i])
		}
		c.APIEndpoints[0].APIKey = vals[0]
	}

	// Support LOG_LEVEL and DD_LOG_LEVEL but prefer DD_LOG_LEVEL
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("DD_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}

	// Logging to console
	if enabled, err := isAffirmative(os.Getenv("DD_LOGS_STDOUT")); err == nil {
		c.LogToConsole = enabled
	}
	if enabled, err := isAffirmative(os.Getenv("LOG_TO_CONSOLE")); err == nil {
		c.LogToConsole = enabled
	}
	if enabled, err := isAffirmative(os.Getenv("DD_LOG_TO_CONSOLE")); err == nil {
		c.LogToConsole = enabled
	}

	if c.proxy, err = proxyFromEnv(c.proxy); err != nil {
		log.Errorf("error parsing proxy settings, not using a proxy: %s", err)
		c.proxy = nil
	}

	if v := os.Getenv("DD_PROCESS_AGENT_URL"); v != "" {
		u, err := url.Parse(v)
		if err != nil {
			log.Warnf("DD_PROCESS_AGENT_URL is invalid: %s", err)
		} else {
			log.Infof("overriding API endpoint from env")
			c.APIEndpoints[0].Endpoint = u
		}
		if site := os.Getenv("DD_SITE"); site != "" {
			log.Infof("Using 'process_dd_url' (%s) and ignoring 'site' (%s)", v, site)
		}
	}

	// Process Arguments Scrubbing
	if enabled, err := isAffirmative(os.Getenv("DD_SCRUB_ARGS")); enabled {
		c.Scrubber.Enabled = true
	} else if !enabled && err == nil {
		c.Scrubber.Enabled = false
	}

	if v := os.Getenv("DD_CUSTOM_SENSITIVE_WORDS"); v != "" {
		c.Scrubber.AddCustomSensitiveWords(strings.Split(v, ","))
	}
	if ok, _ := isAffirmative(os.Getenv("DD_STRIP_PROCESS_ARGS")); ok {
		c.Scrubber.StripAllArguments = true
	}

	if v := os.Getenv("DD_AGENT_PY"); v != "" {
		c.DDAgentPy = v
	}
	if v := os.Getenv("DD_AGENT_PY_ENV"); v != "" {
		c.DDAgentPyEnv = strings.Split(v, ",")
	}

	if v := os.Getenv("DD_DOGSTATSD_PORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil {
			log.Info("Failed to parse DD_DOGSTATSD_PORT: it should be a port number")
		} else {
			c.StatsdPort = port
		}
	}

	if v := os.Getenv("DD_BIND_HOST"); v != "" {
		c.StatsdHost = v
	}

	// Docker config
	if v := os.Getenv("DD_COLLECT_DOCKER_NETWORK"); v == "false" {
		c.CollectDockerNetwork = false
	}
	if v := os.Getenv("DD_CONTAINER_BLACKLIST"); v != "" {
		c.ContainerBlacklist = strings.Split(v, ",")
	}
	if v := os.Getenv("DD_CONTAINER_WHITELIST"); v != "" {
		c.ContainerWhitelist = strings.Split(v, ",")
	}
	if v := os.Getenv("DD_CONTAINER_CACHE_DURATION"); v != "" {
		durationS, _ := strconv.Atoi(v)
		c.ContainerCacheDuration = time.Duration(durationS) * time.Second
	}

	// Used to override container source auto-detection.
	// "docker", "ecs_fargate", "kubelet", etc
	if v := os.Getenv("DD_PROCESS_AGENT_CONTAINER_SOURCE"); v != "" {
		util.SetContainerSource(v)
	}

	// Note: this feature is in development and should not be used in production environments
	// STS: ignore DD notes, this will enable our tcptracer-ebpf and that is production ready
	if ok, _ := isAffirmative(os.Getenv("DD_NETWORK_TRACING_ENABLED")); ok {
		c.EnabledChecks = append(c.EnabledChecks, "connections")
		c.EnableNetworkTracing = ok
	}
	if v := os.Getenv("DD_NETTRACER_SOCKET"); v != "" {
		c.NetworkTracerSocketPath = v
	}

	if v := os.Getenv("STS_PROCESS_BLACKLIST_PATTERNS"); v != "" {
		patterns := strings.Split(v, ",")
		c.Blacklist = deriveFmapConstructRegex(constructRegex, patterns)
	}

	amountTopCPUPercentageUsage, amountTopIOReadUsage, amountTopIOWriteUsage, amountTopMemoryUsage := 0, 0, 0, 0
	CPUPercentageUsageThreshold, memoryUsageThreshold := 0, 0
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_CPU")); err == nil {
		amountTopCPUPercentageUsage = v
	}
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_READ")); err == nil {
		amountTopIOReadUsage = v
	}
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_WRITE")); err == nil {
		amountTopIOWriteUsage = v
	}
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_MEM")); err == nil {
		amountTopMemoryUsage = v
	}
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_CPU_THRESHOLD")); err == nil {
		CPUPercentageUsageThreshold = v
	}
	if v, err := strconv.Atoi(os.Getenv("STS_PROCESS_BLACKLIST_INCLUSIONS_MEM_THRESHOLD")); err == nil {
		memoryUsageThreshold = v
	}
	setBlacklistInclusions(c, amountTopCPUPercentageUsage, amountTopIOReadUsage, amountTopIOWriteUsage, amountTopMemoryUsage,
		CPUPercentageUsageThreshold, memoryUsageThreshold)

	return c
}

func setBlacklistInclusions(agentConf *AgentConfig,
	amountTopCPUPercentageUsage int, amountTopIOReadUsage int, amountTopIOWriteUsage int, amountTopMemoryUsage int,
	CPUPercentageUsageThreshold int, MemoryUsageThreshold int,
) {
	if amountTopCPUPercentageUsage != 0 {
		log.Infof("Overriding top CPU percentage using processes inclusions to %d", amountTopCPUPercentageUsage)
		agentConf.AmountTopCPUPercentageUsage = amountTopCPUPercentageUsage
	}
	if amountTopIOReadUsage != 0 {
		log.Infof("Overriding top IO read using processes inclusions to %d", amountTopIOReadUsage)
		agentConf.AmountTopIOReadUsage = amountTopIOReadUsage
	}
	if amountTopIOWriteUsage != 0 {
		log.Infof("Overriding top IO write using processes inclusions to %d", amountTopIOWriteUsage)
		agentConf.AmountTopIOWriteUsage = amountTopIOWriteUsage
	}
	if amountTopMemoryUsage != 0 {
		log.Infof("Overriding top memory using processes inclusions to %d", amountTopMemoryUsage)
		agentConf.AmountTopMemoryUsage = amountTopMemoryUsage
	}

	// Threshold for retrieving top CPU percentage using processes
	if CPUPercentageUsageThreshold != 0 {
		log.Infof("Overriding CPU percentage threshold for collecting top CPU using processes inclusions to %d", CPUPercentageUsageThreshold)
		agentConf.CPUPercentageUsageThreshold = CPUPercentageUsageThreshold
		if amountTopCPUPercentageUsage <= 0 {
			log.Warn("CPUPercentageUsageThreshold specified without AmountTopCPUPercentageUsage. Please add AmountTopCPUPercentageUsage to benefit from the top process inclusions")
		}
	}

	// Threshold for retrieving top Memory percentage using processes
	if MemoryUsageThreshold != 0 {
		log.Infof("Overriding Memory threshold for collecting top memory using processes inclusions to %d", MemoryUsageThreshold)
		agentConf.MemoryUsageThreshold = MemoryUsageThreshold
		if amountTopMemoryUsage <= 0 {
			log.Warn("MemoryUsageThreshold specified without AmountTopMemoryUsage. Please add AmountTopMemoryUsage to benefit from the top process inclusions")
		}
	}

	// log warning if blacklist inclusions is specified without patterns
	if (agentConf.AmountTopCPUPercentageUsage > 0 ||
		agentConf.AmountTopIOReadUsage > 0 ||
		agentConf.AmountTopIOWriteUsage > 0 ||
		agentConf.AmountTopMemoryUsage > 0) && len(agentConf.Blacklist) == 0 {
		log.Warn("Process blacklist inclusions specified without a blacklist pattern. Please add process blacklist patterns to benefit from the top process inclusions")
	}

}

func constructRegex(pattern string) *regexp.Regexp {
	r, err := regexp.Compile(pattern)
	if err != nil {
		log.Warnf("Invalid blacklist pattern: %s", pattern)
	}
	return r
}

// IsBlacklisted returns a boolean indicating if the given command is blacklisted by our config.
func IsBlacklisted(cmdline []string, blacklist []*regexp.Regexp) bool {
	cmd := strings.Join(cmdline, " ")
	for _, b := range blacklist {
		if b.MatchString(cmd) {
			return true
		}
	}
	return false
}

func isAffirmative(value string) (bool, error) {
	if value == "" {
		return false, fmt.Errorf("value is empty")
	}
	v := strings.ToLower(value)
	return v == "true" || v == "yes" || v == "1", nil
}

// getHostname shells out to obtain the hostname used by the infra agent
// falling back to os.Hostname() if it is unavailable
func getHostname(ddAgentPy, ddAgentBin string, ddAgentEnv []string) (string, error) {
	var cmd *exec.Cmd
	// In Agent 6 we will have an Agent binary defined.
	if ddAgentBin != "" {
		cmd = exec.Command(ddAgentBin, "hostname")
	} else {
		getHostnameCmd := "from utils.hostname import get_hostname; print get_hostname()"
		cmd = exec.Command(ddAgentPy, "-c", getHostnameCmd)
	}

	// Copying all environment variables to child process
	// Windows: Required, so the child process can load DLLs, etc.
	// Linux:   Optional, but will make use of DD_HOSTNAME and DOCKER_DD_AGENT if they exist
	osEnv := os.Environ()
	cmd.Env = append(ddAgentEnv, osEnv...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Infof("error retrieving dd-agent hostname, falling back to os.Hostname(): %v", err)
		return os.Hostname()
	}

	hostname := strings.TrimSpace(stdout.String())

	if hostname == "" {
		log.Infof("error retrieving dd-agent hostname, falling back to os.Hostname(): %s", stderr.String())
		return os.Hostname()
	}

	return hostname, err
}

// getProxySettings returns a url.Url for the proxy configuration from datadog.conf, if available.
// In the case of invalid settings an error is logged and nil is returned. If settings are missing,
// meaning we don't want a proxy, then nil is returned with no error.
func getProxySettings(m *ini.Section) (proxyFunc, error) {
	var host string
	scheme := "http"
	if v := m.Key("proxy_host").MustString(""); v != "" {
		// accept either http://myproxy.com or myproxy.com
		if i := strings.Index(v, "://"); i != -1 {
			// when available, parse the scheme from the url
			scheme = v[0:i]
			host = v[i+3:]
		} else {
			host = v
		}
	}

	if host == "" {
		return nil, nil
	}

	port := defaultProxyPort
	if v := m.Key("proxy_port").MustInt(-1); v != -1 {
		port = v
	}
	var user, password string
	if v := m.Key("proxy_user").MustString(""); v != "" {
		user = v
	}
	if v := m.Key("proxy_password").MustString(""); v != "" {
		password = v
	}
	return constructProxy(host, scheme, port, user, password)
}

// proxyFromEnv parses out the proxy configuration from the ENV variables in a
// similar way to getProxySettings and, if enough values are available, returns
// a new proxy URL value. If the environment is not set for this then the
// `defaultVal` is returned.
func proxyFromEnv(defaultVal proxyFunc) (proxyFunc, error) {
	var host string
	scheme := "http"
	if v := os.Getenv("PROXY_HOST"); v != "" {
		// accept either http://myproxy.com or myproxy.com
		if i := strings.Index(v, "://"); i != -1 {
			// when available, parse the scheme from the url
			scheme = v[0:i]
			host = v[i+3:]
		} else {
			host = v
		}
	}

	if host == "" {
		return defaultVal, nil
	}

	port := defaultProxyPort
	if v := os.Getenv("PROXY_PORT"); v != "" {
		port, _ = strconv.Atoi(v)
	}
	var user, password string
	if v := os.Getenv("PROXY_USER"); v != "" {
		user = v
	}
	if v := os.Getenv("PROXY_PASSWORD"); v != "" {
		password = v
	}

	return constructProxy(host, scheme, port, user, password)
}

// constructProxy constructs a *url.Url for a proxy given the parts of a
// Note that we assume we have at least a non-empty host for this call but
// all other values can be their defaults (empty string or 0).
func constructProxy(host, scheme string, port int, user, password string) (proxyFunc, error) {
	var userpass *url.Userinfo
	if user != "" {
		if password != "" {
			userpass = url.UserPassword(user, password)
		} else {
			userpass = url.User(user)
		}
	}

	var path string
	if userpass != nil {
		path = fmt.Sprintf("%s@%s:%v", userpass.String(), host, port)
	} else {
		path = fmt.Sprintf("%s:%v", host, port)
	}
	if scheme != "" {
		path = fmt.Sprintf("%s://%s", scheme, path)
	}

	u, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	return http.ProxyURL(u), nil
}
