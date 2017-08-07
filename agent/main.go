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

	"github.com/DataDog/datadog-process-agent/checks"
	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/util/docker"
	"github.com/DataDog/datadog-process-agent/util/ecs"
	"github.com/DataDog/datadog-process-agent/util/kubernetes"
)

var opts struct {
	ddConfigPath string
	configPath   string
	debug        bool
	version      bool
	check        string
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
	flag.StringVar(&opts.ddConfigPath, "ddconfig", "/etc/dd-agent/datadog.conf", "Path to dd-agent config")
	flag.StringVar(&opts.configPath, "config", "/etc/dd-agent/dd-process-agent.ini", "DEPRECATED: Path to legacy config file. Prefer -ddconfig to point to the dd-agent config")
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

	// Run a profile server.
	go func() {
		http.ListenAndServe("localhost:6062", nil)
	}()

	agentConf, err := config.NewIfExists(opts.ddConfigPath)
	if err != nil {
		log.Criticalf("Error reading dd-agent config: %s", err)
		os.Exit(1)
	}
	legacyConf, err := config.NewIfExists(opts.configPath)
	if err != nil {
		log.Criticalf("Error reading legacy config: %s", err)
		os.Exit(1)
	}
	cfg, err := config.NewAgentConfig(agentConf, legacyConf)
	if err != nil {
		log.Criticalf("Error parsing config: %s", err)
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
	initMetadataProviders(cfg)

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

	cl, err := NewCollector(cfg)
	if err != nil {
		log.Criticalf("Error creating collector: %s", err)
		os.Exit(1)
		return
	}
	cl.run()
}

func initMetadataProviders(cfg *config.AgentConfig) {
	err := docker.InitDockerUtil(cfg.CollectDockerHealth, cfg.CollectDockerNetwork)
	if err != nil && err != docker.ErrDockerNotAvailable {
		log.Errorf("unable to initialize docker collection: %s", err)
	}

	err = kubernetes.InitKubeUtil(cfg)
	if err != nil && err != kubernetes.ErrKubernetesNotAvailable {
		log.Errorf("unable to initialize kubernetes collection: %s", err)
	}

	err = ecs.InitECSUtil()
	if err != nil && err != ecs.ErrECSNotAvailable {
		log.Errorf("unable to initialize ECS collection: %s", err)
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

	switch check {
	case "process":
		p := checks.NewProcessCheck(cfg, sysInfo)
		return printResults(cfg, p)
	case "connections":
		p := checks.NewConnectionsCheck(cfg, sysInfo)
		return printResults(cfg, p)
	case "realtime":
		p := checks.NewRealTimeCheck(cfg, sysInfo)
		return printResults(cfg, p)
	default:
		return fmt.Errorf("invalid check: %s", check)
	}
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
