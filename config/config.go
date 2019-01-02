package config

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/DataDog/datadog-process-agent/util"

	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	ecsutil "github.com/DataDog/datadog-agent/pkg/util/ecs"

	log "github.com/cihub/seelog"
)

var (
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

	// Network collection configuration
	EnableNetworkTracing     bool
	EnableLocalNetworkTracer bool // To have the network tracer embedded in the process-agent
	DisableTCPTracing        bool
	DisableUDPTracing        bool
	DisableIPv6Tracing       bool
	NetworkTracerSocketPath  string
	NetworkTracerLogFile     string

	// Check config
	EnabledChecks  []string
	CheckIntervals map[string]time.Duration

	// Containers
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

func initConfig(dc ddconfig.Config) {
	dc.BindEnv(keyLogFile)
	// All the following durations are in seconds
	dc.BindEnv(keyQueueSize)
	dc.BindEnv(keyMaxProcFDs)
	dc.BindEnv(keyMaxPerMessage)

	dc.BindEnv(keyWinAddNewArgs)

	// Variables that don't have the same name in the config and in the env

	dc.BindEnv(keyDDURL, envDDURL)
	dc.BindEnv(keyEnabled, envEnabled)
	dc.BindEnv(keyDDAgentBin, envDDAgentBin)
	dc.BindEnv(keyDDAgentEnv, envDDAgentEnv)
	dc.BindEnv(keyDDAgentPy, envDDAgentPy)
	dc.BindEnv(keyDDAgentPyEnv, envDDAgentPyEnv)
	dc.BindEnv(keyScrubArgs, envScrubArgs)
	dc.BindEnv(keyCustomSensitiveWords, envCustomSensitiveWords)
	dc.BindEnv(keyStripProcessArguments, envStripProcessArguments)
	dc.BindEnv(keyAPIKey)

	// Network tracer config

	dc.BindEnv(keyNetworkLogFile)

	// Variables that don't have the same name in the config and in the env
	dc.BindEnv(keyNetworkTracingEnabled, envNetworkTracingEnabled)
	dc.BindEnv(keyNetworkUnixSocketPath, envNetworkUnixSocketPath)
	dc.BindEnv(keyNetworkDisableTCPTracing, envNetworkDisableTCPTracing)
	dc.BindEnv(keyNetworkDisableUDPTracing, envNetworkDisableUDPTracing)
	dc.BindEnv(keyNetworkDisableIPV6Tracing, envNetworkDisableIPV6Tracing)
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
		MaxPerMessage: 100,
		AllowRealTime: true,
		HostName:      "",
		Transport:     NewDefaultTransport(),

		// Statsd for internal instrumentation
		StatsdHost: "127.0.0.1",
		StatsdPort: 8125,

		DDAgentBin: defaultDDAgentBin,

		// Path and environment for the dd-agent embedded python
		DDAgentPy:    defaultDDAgentPy,
		DDAgentPyEnv: []string{defaultDDAgentPyEnv},

		// Network collection configuration
		EnableNetworkTracing:     false,
		EnableLocalNetworkTracer: false,
		DisableTCPTracing:        false,
		DisableUDPTracing:        false,
		DisableIPv6Tracing:       false,
		NetworkTracerSocketPath:  defaultNetworkTracerSocketPath,
		NetworkTracerLogFile:     defaultNetworkLogFilePath,

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

	return ac
}

// NewAgentConfig returns an AgentConfig using a configuration file. It can be nil
// if there is no file available. In this case we'll configure only via environment.
func NewAgentConfig(dc ddconfig.Config, agentIni, agentYaml, networkYaml io.Reader) (*AgentConfig, error) {
	// Init the bindings
	initConfig(dc)

	// Set config type otherwise we won't be able to use io.Readers
	dc.SetConfigType("yaml")

	// Read process config
	if agentYaml != nil {
		if err := dc.ReadConfig(agentYaml); err != nil {
			return nil, fmt.Errorf("error reading the agent yaml config: %s", err)
		}
	}

	// Merge network config
	if networkYaml != nil {
		if err := dc.MergeConfig(networkYaml); err != nil {
			return nil, fmt.Errorf("error reading the network yaml config: %s", err)
		}
	}

	var err error

	// Initialize default config
	cfg := NewDefaultAgentConfig()

	// Pull from the ini Agent config by default.
	if agentIni != nil {
		if err = mergeIniConfig(agentIni, cfg); err != nil {
			return nil, fmt.Errorf("error reading the ini config")
		}
	}

	if err = mergeConfig(dc, cfg); err != nil {
		return nil, err
	}

	// Environment variables
	mergeEnvironmentVariablesOnly(dc, cfg)

	// Python-style log level has WARNING vs WARN
	if strings.ToLower(cfg.LogLevel) == "warning" {
		cfg.LogLevel = "warn"
	}

	// (Re)configure the logging from our configuration
	if err := NewLoggerLevel(cfg.LogLevel, cfg.LogFile, cfg.LogToConsole); err != nil {
		return nil, err
	}

	if networkYaml != nil {
		// (Re)configure the logging from our configuration, with the network tracer logfile
		if err := NewLoggerLevel(cfg.LogLevel, cfg.NetworkTracerLogFile, cfg.LogToConsole); err != nil {
			return nil, fmt.Errorf("failed to setup network-tracer logger: %s", err)
		}
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

// NewReaderIfExists returns a new io.Reader if the given configPath is exists.
func NewReaderIfExists(configPath string) (io.Reader, error) {
	if !util.PathExists(configPath) {
		return nil, nil
	}

	raw, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read error: %s", err)
	}
	return bytes.NewBuffer(raw), nil
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
