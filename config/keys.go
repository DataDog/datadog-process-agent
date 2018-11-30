package config

// Prefixes
const procPrefix = "process_config."
const networkPrefix = "network_tracer_config."
const intervalsPrefix = procPrefix + "intervals."
const windowsPrefix = procPrefix + "windows."

// List of the keys used in the yaml configuration and environment
// keyXXX -> YAML
// envXXX -> Environment
const (
	// Top level
	keyDDURL  = "dd_url"
	keyAPIKey = "api_key"
	envDDURL  = "DD_PROCESS_AGENT_URL"

	// All keys in the Yaml file
	// A string indicate the enabled state of the Agent.
	// If "false" (the default) we will only collect containers.
	// If "true" we will collect containers and processes.
	// If "disabled" the agent will be disabled altogether and won't start.
	keyEnabled = procPrefix + "enabled"
	envEnabled = "DD_PROCESS_AGENT_ENABLED"

	// The full path to the file where process-agent logs will be written.
	keyLogFile = procPrefix + "log_file"

	// The interval, in seconds, at which we will run each check. If you want consistent
	// behavior between real-time you may set the Container/ProcessRT intervals to 10.
	keyIntervalsContainer   = intervalsPrefix + "container"
	keyIntervalsContainerRT = intervalsPrefix + "container_realtime"
	keyIntervalsProcess     = intervalsPrefix + "process"
	keyIntervalsProcessRT   = intervalsPrefix + "process_realtime"
	keyIntervalsConnections = intervalsPrefix + "connections"

	// A list of regex patterns that will exclude a process if matched.
	keyBlacklistPatterns = procPrefix + "blacklist_patterns"
	// Enable/Disable the DataScrubber to obfuscate process args
	keyScrubArgs = procPrefix + "scrub_args"
	envScrubArgs = "DD_SCRUB_ARGS"

	// A custom word list to enhance the default one used by the DataScrubber
	keyCustomSensitiveWords = procPrefix + "custom_sensitive_words"
	envCustomSensitiveWords = "DD_CUSTOM_SENSITIVE_WORDS"

	// Strips all process arguments
	keyStripProcessArguments = procPrefix + "strip_proc_arguments"
	envStripProcessArguments = "DD_STRIP_PROCESS_ARGS"

	// How many check results to buffer in memory when POST fails. The default is usually fine.
	keyQueueSize = procPrefix + "queue_size"
	// The maximum number of file descriptors to open when collecting net connections.
	// Only change if you are running out of file descriptors from the Agent.
	keyMaxProcFDs = procPrefix + "max_proc_fds"
	// The maximum number of processes, connections or containers per message.
	// Only change if the defaults are causing issues.
	keyMaxPerMessage = procPrefix + "max_per_message"
	// Overrides the path to the Agent bin used for getting the hostname. The default is usually fine.
	keyDDAgentBin = procPrefix + "dd_agent_bin"
	envDDAgentBin = "DD_AGENT_BIN"

	// Overrides of the environment we pass to fetch the hostname. The default is usually fine.
	keyDDAgentEnv = procPrefix + "dd_agent_env"
	envDDAgentEnv = "DD_AGENT_ENV"

	keyDDAgentPy = procPrefix + "dd_agent_py"
	envDDAgentPy = "DD_AGENT_PY"

	// Comma separated env variables
	keyDDAgentPyEnv = procPrefix + "dd_agent_py_env"
	envDDAgentPyEnv = "DD_AGENT_PY_ENV"

	// Optional additional pairs of endpoint_url => []apiKeys to submit to other locations.
	keyAdditionalEndpoints = procPrefix + "additional_endpoints"

	// Windows config

	// Sets windows process table refresh rate (in number of check runs)
	keyWinArgsRefreshInterval = windowsPrefix + "args_refresh_interval"
	// Controls getting process arguments immediately when a new process is discovered
	keyWinAddNewArgs = windowsPrefix + "add_new_args"

	// Network tracer config
	// A string indicating the enabled state of the network tracer.
	keyNetworkTracingEnabled = networkPrefix + "enabled"
	envNetworkTracingEnabled = "DD_NETWORK_TRACING_ENABLED"

	// The full path to the location of the unix socket where network traces will be accessed
	keyNetworkUnixSocketPath = networkPrefix + "nettracer_socket"
	envNetworkUnixSocketPath = "DD_NETTRACER_SOCKET"

	// The full path to the file where network-tracer logs will be written.
	keyNetworkLogFile = networkPrefix + "log_file"

	// Whether agent should disable collection for TCP connection type
	keyNetworkDisableTCPTracing = networkPrefix + "disable_tcp"
	envNetworkDisableTCPTracing = "DD_DISABLE_TCP_TRACING"

	// Whether agent should disable collection for UDP connection type
	keyNetworkDisableUDPTracing = networkPrefix + "disable_udp"
	envNetworkDisableUDPTracing = "DD_DISABLE_UDP_TRACING"

	// Whether agent should disable collection for IPV6 connection type
	keyNetworkDisableIPV6Tracing = networkPrefix + "disable_ipv6"
	envNetworkDisableIPV6Tracing = "DD_DISABLE_IPV6_TRACING"
)
