package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-agent/pkg/pidfile"
	"github.com/DataDog/datadog-agent/pkg/tagger"
	"github.com/DataDog/datadog-agent/pkg/util/docker"
	"github.com/DataDog/datadog-process-agent/checks"
	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/statsd"
	"github.com/DataDog/datadog-process-agent/util"
	"github.com/DataDog/datadog-process-agent/util/kubernetes"
)

var opts struct {
	configPath   string
	ddConfigPath string
	pidfilePath  string
	debug        bool
	version      bool
	check        string
	info         bool
}

// version info sourced from build flags
var (
	Version   string
	GitCommit string
	GitBranch string
	BuildDate string
	GoVersion string
)

// versionString returns the version information filled in at build time
func versionString() string {
	var buf bytes.Buffer

	if Version != "" {
		fmt.Fprintf(&buf, "Version: %s\n", Version)
	}
	if GitCommit != "" {
		fmt.Fprintf(&buf, "Git hash: %s\n", GitCommit)
	}
	if GitBranch != "" {
		fmt.Fprintf(&buf, "Git branch: %s\n", GitBranch)
	}
	if BuildDate != "" {
		fmt.Fprintf(&buf, "Build date: %s\n", BuildDate)
	}
	if GoVersion != "" {
		fmt.Fprintf(&buf, "Go Version: %s\n", GoVersion)
	}

	return buf.String()
}

const agentDisabledMessage = `process-agent not enabled.
Set env var DD_PROCESS_AGENT_ENABLED=true or add
process_agent_enabled: true
to your datadog.conf file.
Exiting.`

func main() {
	flag.StringVar(&opts.configPath, "config", "/etc/datadog-agent/datadog.yaml", "Path to datadog.yaml config")
	flag.StringVar(&opts.ddConfigPath, "ddconfig", "/etc/dd-agent/datadog.conf", "Path to dd-agent config")
	flag.StringVar(&opts.pidfilePath, "pid", "", "Path to set pidfile for process")
	flag.BoolVar(&opts.info, "info", false, "Show info about running process agent and exit")
	flag.BoolVar(&opts.version, "version", false, "Print the version and exit")
	flag.StringVar(&opts.check, "check", "", "Run a specific check and print the results. Choose from: process, connections, realtime")
	flag.Parse()

	// Set up a default config before parsing config so we log errors nicely.
	// The default will be stdout since we can't assume any file is writeable.
	if err := config.NewLoggerLevel("info", ""); err != nil {
		panic(err)
	}

	if opts.version {
		fmt.Println(versionString())
		os.Exit(0)
	}

	if opts.check == "" && !opts.info && opts.pidfilePath != "" {
		err := pidfile.WritePID(opts.pidfilePath)
		if err != nil {
			log.Errorf("Error while writing PID file, exiting: %v", err)
			os.Exit(1)
		}

		log.Infof("pid '%d' written to pid file '%s'", os.Getpid(), opts.pidfilePath)
		defer func() {
			// remove pidfile if set
			os.Remove(opts.pidfilePath)
		}()
	}

	agentConf, err := config.NewIfExists(opts.ddConfigPath)
	if err != nil {
		log.Criticalf("Error reading dd-agent config: %s", err)
		os.Exit(1)
	}

	yamlConf, err := config.NewYamlIfExists(opts.configPath)
	if err != nil {
		log.Criticalf("Error reading datadog.yaml: %s", err)
		os.Exit(1)
	}
	if yamlConf != nil {
		config.SetupDDAgentConfig(opts.configPath)
	}

	if err := tagger.Init(); err == nil {
		defer tagger.Stop()
	} else {
		log.Errorf("unable to initialize Datadog entity tagger: %s", err)
	}

	cfg, err := config.NewAgentConfig(agentConf, yamlConf)
	if err != nil {
		log.Criticalf("Error parsing config: %s", err)
		os.Exit(1)
	}
	err = initInfo(cfg)
	if err != nil {
		log.Criticalf("Error initializing info: %s", err)
		os.Exit(1)
	}
	if err := statsd.Configure(cfg); err != nil {
		log.Criticalf("Error configuring statsd: %s", err)
		os.Exit(1)
	}

	// Exit if agent is not enabled and we're not debugging a check.
	if !cfg.Enabled && opts.check == "" {
		log.Info(agentDisabledMessage)

		// a sleep is necessary to ensure that supervisor registers this process as "STARTED"
		// If the exit is "too quick", we enter a BACKOFF->FATAL loop even though this is an expected exit
		// http://supervisord.org/subprocess.html#process-states
		time.Sleep(5 * time.Second)
		return
	}

	// Initialize the metadata providers so the singletons are available.
	// This will log any unknown errors
	initMetadataProviders()

	// update docker socket path in info
	dockerSock, err := util.GetDockerSocketPath()
	if err != nil {
		log.Debugf("Docker is not available on this host")
	}
	// we shouldn't quit because docker is not required. If no docker docket is available,
	// we just pass down empty string
	updateDockerSocket(dockerSock)

	log.Debug("Running process-agent with DEBUG logging enabled")
	if opts.check != "" {
		err := debugCheckResults(cfg, opts.check)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			os.Exit(0)
		}
		return
	}

	if opts.info {
		// using the debug port to get info to work
		url := "http://localhost:6062/debug/vars"
		if err := Info(os.Stdout, cfg, url); err != nil {
			os.Exit(1)
		}
		return
	}

	// Run a profile server.
	go func() {
		http.ListenAndServe("localhost:6062", nil)
	}()

	cl, err := NewCollector(cfg)
	if err != nil {
		log.Criticalf("Error creating collector: %s", err)
		os.Exit(1)
		return
	}
	cl.run()
}

func initMetadataProviders() {
	if _, err := docker.GetDockerUtil(); err != nil && err != docker.ErrDockerNotAvailable {
		log.Errorf("unable to initialize docker collection: %s", err)
	}

	if err := kubernetes.InitKubeUtil(); err != nil {
		log.Errorf("unable to initialize kubernetes collection: %s", err)
	}
}

// Handles signals - tells us whether we should exit.
func handleSignals(exit chan bool) {
	sigIn := make(chan os.Signal, 100)
	signal.Notify(sigIn)
	// unix only in all likelihood;  but we don't care.
	for sig := range sigIn {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			log.Criticalf("Caught signal '%s'; terminating.", sig)
			close(exit)
		case syscall.SIGCHLD:
			// Running docker.GetDockerStat() spins up / kills a new process
			continue
		default:
			log.Warnf("Caught signal %s; continuing/ignoring.", sig)
		}
	}
}

func debugCheckResults(cfg *config.AgentConfig, check string) error {
	sysInfo, err := checks.CollectSystemInfo(cfg)
	if err != nil {
		return err
	}

	names := make([]string, 0, len(checks.All))
	for _, ch := range checks.All {
		if ch.Name() == check {
			ch.Init(cfg, sysInfo)
			return printResults(cfg, ch)
		}
		names = append(names, ch.Name())
	}
	return fmt.Errorf("invalid check '%s', choose from: %v", check, names)
}

func printResults(cfg *config.AgentConfig, ch checks.Check) error {
	// Run the check once to prime the cache.
	_, err := ch.Run(cfg, 0)
	if err != nil {
		return fmt.Errorf("collection error: %s", err)
	}
	time.Sleep(1 * time.Second)

	fmt.Printf("-----------------------------\n\n")
	fmt.Printf("\nResults for check %s\n", ch.Name())
	fmt.Printf("-----------------------------\n\n")

	msgs, err := ch.Run(cfg, 1)
	if err != nil {
		return fmt.Errorf("collection error: %s", err)
	}

	for _, m := range msgs {
		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal error: %s", err)
		}
		fmt.Println(string(b))
	}
	return nil
}
