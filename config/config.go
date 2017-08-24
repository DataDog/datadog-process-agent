package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-process-agent/util"
	"github.com/DataDog/datadog-process-agent/util/docker"
	"github.com/DataDog/datadog-process-agent/util/kubernetes"
	log "github.com/cihub/seelog"
	"github.com/go-ini/ini"
)

var (
	processChecks   = []string{"process", "rtprocess"}
	containerChecks = []string{"container", "rtcontainer"}

	// List of known Kubernetes images that we want to exclude by default.
	defaultKubeBlacklist = []string{
		"image:gcr.io/google_containers/pause.*",
		"image:openshift/origin-pod",
	}
)

// AgentConfig is the global config for the process-agent. This information
// is sourced from config files and the environment variables.
type AgentConfig struct {
	Enabled       bool
	APIKey        string
	HostName      string
	APIEndpoint   *url.URL
	LogFile       string
	LogLevel      string
	QueueSize     int
	Blacklist     []*regexp.Regexp
	MaxProcFDs    int
	ProcLimit     int
	AllowRealTime bool
	Proxy         *url.URL
	Logger        *LoggerConfig
	DDAgentPy     string
	DDAgentPyEnv  []string

	// Check config
	EnabledChecks  []string
	CheckIntervals map[string]time.Duration

	// Docker
	ContainerBlacklist     []string
	ContainerWhitelist     []string
	CollectDockerNetwork   bool
	ContainerCacheDuration time.Duration

	// Kubernetes
	CollectKubernetesMetadata  bool
	KubernetesKubeletHost      string
	KubernetesHTTPKubeletPort  int
	KubernetesHTTPSKubeletPort int
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
	maxProcLimit    = 100
)

// NewDefaultAgentConfig returns an AgentConfig with defaults initialized
func NewDefaultAgentConfig() *AgentConfig {
	u, err := url.Parse(defaultEndpoint)
	if err != nil {
		// This is a hardcoded URL so parsing it should not fail
		panic(err)
	}
	ac := &AgentConfig{
		// We'll always run inside of a container.
		Enabled:       docker.IsContainerized() || docker.IsAvailable(),
		APIEndpoint:   u,
		LogFile:       defaultLogFilePath,
		LogLevel:      "info",
		QueueSize:     20,
		MaxProcFDs:    200,
		ProcLimit:     100,
		AllowRealTime: true,

		// Path and environment for the dd-agent embedded python
		DDAgentPy:    "/opt/datadog-agent/embedded/bin/python",
		DDAgentPyEnv: []string{"PYTHONPATH=/opt/datadog-agent/agent"},

		// Check config
		EnabledChecks: containerChecks,
		CheckIntervals: map[string]time.Duration{
			"process":     10 * time.Second,
			"rtprocess":   2 * time.Second,
			"container":   10 * time.Second,
			"rtcontainer": 2 * time.Second,
			"connections": 3 * 60 * time.Minute,
		},

		// Docker
		ContainerCacheDuration: 10 * time.Second,
		CollectDockerNetwork:   true,

		// Kubernetes
		CollectKubernetesMetadata:  true,
		KubernetesHTTPKubeletPort:  10255,
		KubernetesHTTPSKubeletPort: 10250,
	}

	// Set default values for proc/sys paths if unset.
	if docker.IsContainerized() {
		if v := os.Getenv("HOST_PROC"); v == "" {
			os.Setenv("HOST_PROC", "/host/proc")
		}
		if v := os.Getenv("HOST_SYS"); v == "" {
			os.Setenv("HOST_SYS", "/host/sys")
		}
	}
	// Kubernetes
	if kubernetes.IsKubernetes() {
		ac.ContainerBlacklist = defaultKubeBlacklist
	}

	return ac
}

// NewAgentConfig returns an AgentConfig using a conf and legacy configuration.
// conf will be nil if there is no configuration available but legacyConf will
// give an error if nil.
func NewAgentConfig(agentConf, legacyConf *File) (*AgentConfig, error) {
	cfg := NewDefaultAgentConfig()

	var ns string
	var file *File
	var section *ini.Section
	if agentConf != nil {
		section, _ = agentConf.GetSection("Main")
	}

	// Prefer the dd-agent config file.
	if section != nil {
		file = agentConf
		ns = "process.config"
		a, err := agentConf.Get("Main", "api_key")
		if err != nil {
			return nil, err
		}
		ak := strings.Split(a, ",")
		cfg.APIKey = ak[0]
		cfg.LogLevel = strings.ToLower(agentConf.GetDefault("Main", "log_level", "INFO"))
		cfg.Proxy = getProxySettings(section)
		e := agentConf.GetDefault(ns, "endpoint", defaultEndpoint)
		u, err := url.Parse(e)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint URL: %s", err)
		}
		if v, _ := agentConf.Get("Main", "process_agent_enabled"); v == "false" {
			cfg.Enabled = false
		} else if v == "true" {
			cfg.Enabled = true
			cfg.EnabledChecks = processChecks
		}

		cfg.APIEndpoint = u
	}

	// But legacy conf will override dd-agent.
	if legacyConf != nil {
		file = legacyConf
		ns = "dd-process-agent"
		cfg.LogLevel = strings.ToLower(legacyConf.GetDefault(ns, "log_level", cfg.LogLevel))

		s, err := legacyConf.Get(ns, "server_url")
		if err != nil {
			return nil, err
		}
		u, err := url.Parse(s)
		if err != nil {
			return nil, err
		}
		cfg.APIEndpoint = u

		a, err := legacyConf.Get(ns, "api_key")
		if err != nil {
			return nil, err
		}
		cfg.APIKey = a
		proxy := legacyConf.GetDefault(ns, "proxy", "")
		if proxy != "" {
			cfg.Proxy, err = url.Parse(proxy)
			if err != nil {
				log.Errorf("Could not parse proxy url from configuration: %s", err)
			}
		}
	}

	// We can have no configuration in ENV-only case.
	if file != nil {
		cfg.QueueSize = file.GetIntDefault(ns, "queue_size", cfg.QueueSize)
		cfg.MaxProcFDs = file.GetIntDefault(ns, "max_proc_fds", cfg.MaxProcFDs)
		cfg.AllowRealTime = file.GetBool(ns, "allow_real_time", cfg.AllowRealTime)
		cfg.LogFile = file.GetDefault(ns, "log_file", cfg.LogFile)
		cfg.DDAgentPy = file.GetDefault(ns, "dd_agent_py", cfg.DDAgentPy)
		cfg.DDAgentPyEnv = file.GetStrArrayDefault(ns, "dd_agent_py_env", ",", cfg.DDAgentPyEnv)

		blacklistPats := file.GetStrArrayDefault(ns, "blacklist", ",", []string{})
		blacklist := make([]*regexp.Regexp, 0, len(blacklistPats))
		for _, b := range blacklistPats {
			r, err := regexp.Compile(b)
			if err == nil {
				blacklist = append(blacklist, r)
			}
		}
		cfg.Blacklist = blacklist
		procLimit := file.GetIntDefault(ns, "proc_limit", cfg.ProcLimit)
		if procLimit <= maxProcLimit {
			cfg.ProcLimit = procLimit
		} else {
			log.Warn("Overriding the configured process limit because it exceeds maximum")
			cfg.ProcLimit = maxProcLimit
		}

		// Checks intervals can be overriden by configuration.
		for checkName, defaultInterval := range cfg.CheckIntervals {
			key := fmt.Sprintf("%s_interval", checkName)
			interval := file.GetDurationDefault(ns, key, time.Second, defaultInterval)
			if interval != defaultInterval {
				log.Infof("Overriding check interval for %s to %s", checkName, interval)
				cfg.CheckIntervals[checkName] = interval
			}
		}

		// Docker config
		cfg.CollectDockerNetwork = file.GetBool(ns, "collect_docker_network", cfg.CollectDockerNetwork)
		cfg.ContainerBlacklist = file.GetStrArrayDefault(ns, "container_blacklist", ",", cfg.ContainerBlacklist)
		cfg.ContainerWhitelist = file.GetStrArrayDefault(ns, "container_whitelist", ",", cfg.ContainerWhitelist)
		cfg.ContainerCacheDuration = file.GetDurationDefault(ns, "container_cache_duration", time.Second, 30*time.Second)
	}

	cfg = mergeEnv(cfg)

	// (Re)configure the logging from our configuration
	if err := NewLoggerLevel(cfg.LogLevel, cfg.LogFile); err != nil {
		return nil, err
	}

	hostname, err := getHostname(cfg.DDAgentPy, cfg.DDAgentPyEnv)
	if err != nil {
		hostname = ""
	}
	cfg.HostName = hostname

	return cfg, nil
}

// mergeEnv applies overrides from environment variables to the trace agent configuration
func mergeEnv(c *AgentConfig) *AgentConfig {
	if v := os.Getenv("DD_PROCESS_AGENT_ENABLED"); v == "false" {
		c.Enabled = false
	} else if v == "true" {
		c.Enabled = true
		c.EnabledChecks = processChecks
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
		log.Info("overriding API key from env DD_API_KEY value")
	}
	if apiKey != "" {
		vals := strings.Split(apiKey, ",")
		for i := range vals {
			vals[i] = strings.TrimSpace(vals[i])
		}
		c.APIKey = vals[0]
	}

	// Support LOG_LEVEL and DD_LOG_LEVEL but prefer DD_LOG_LEVEL
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("DD_LOG_LEVEL"); v != "" {
		c.LogLevel = v
	}
	if v := os.Getenv("DD_LOGS_STDOUT"); v == "true" {
		// Empty log file implies logging to stdout and stdout
		c.LogFile = ""
	}

	c.Proxy = proxyFromEnv(c.Proxy)

	if v := os.Getenv("DD_PROCESS_AGENT_URL"); v != "" {
		u, err := url.Parse(v)
		if err != nil {
			log.Warnf("DD_PROCESS_AGENT_URL is invalid: %s", err)
		} else {
			log.Infof("overriding API endpoint from env")
			c.APIEndpoint = u
		}
	}

	if v := os.Getenv("DD_AGENT_PY"); v != "" {
		c.DDAgentPy = v
	}
	if v := os.Getenv("DD_AGENT_PY_ENV"); v != "" {
		c.DDAgentPyEnv = strings.Split(v, ",")
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

	// Kubernetes config is set via environment only (for now).
	if v := os.Getenv("DD_COLLECT_KUBERNETES_METADATA"); v == "false" {
		c.CollectKubernetesMetadata = false
	}
	if v := os.Getenv("DD_KUBERNETES_KUBELET_HOST"); v != "" {
		c.KubernetesKubeletHost = v
	}
	if v := os.Getenv("DD_KUBERNETES_KUBELET_HTTP_PORT"); v != "" {
		c.KubernetesHTTPKubeletPort, _ = strconv.Atoi(v)
	}
	if v := os.Getenv("DD_KUBERNETES_KUBELET_HTTPS_PORT"); v == "false" {
		c.KubernetesHTTPSKubeletPort, _ = strconv.Atoi(v)
	}

	return c
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

// getHostname shells out to obtain the hostname used by the infra agent
// falling back to os.Hostname() if it is unavailable
func getHostname(ddAgentPy string, ddAgentEnv []string) (string, error) {
	getHostnameCmd := "from utils.hostname import get_hostname; print get_hostname()"

	cmd := exec.Command(ddAgentPy, "-c", getHostnameCmd)
	dockerEnv := os.Getenv("DOCKER_DD_AGENT")
	cmd.Env = append(ddAgentEnv, fmt.Sprintf("DOCKER_DD_AGENT=%s", dockerEnv))

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
func getProxySettings(m *ini.Section) *url.URL {
	var host, scheme string
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
		return nil
	}

	var port int
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
func proxyFromEnv(defaultVal *url.URL) *url.URL {
	var host, scheme string
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
		return defaultVal
	}

	var port int
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
func constructProxy(host, scheme string, port int, user, password string) *url.URL {
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
		path = fmt.Sprintf("%s://%s@%s:%v", scheme, userpass.String(), host, port)
	} else {
		path = fmt.Sprintf("%s://%s:%v", scheme, host, port)
	}

	u, err := url.Parse(path)
	if err != nil {
		log.Errorf("error parsing proxy settings, not using a proxy: %s", err)
		return nil
	}
	return u
}
