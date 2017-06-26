package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/checks"
	"github.com/DataDog/datadog-process-agent/config"
)

var opts struct {
	ddConfigPath string
	configPath   string
	debug        bool
	version      bool
	check        string
}

func main() {
	flag.StringVar(&opts.ddConfigPath, "ddconfig", "/etc/dd-agent/datadog.conf", "Path to dd-agent config")
	flag.StringVar(&opts.configPath, "config", "/etc/dd-agent/dd-process-agent.ini", "DEPRECATED: Path to legacy config file. Prefer -ddconfig to point to the dd-agent config")
	flag.BoolVar(&opts.version, "version", false, "Print the version and exit")
	flag.StringVar(&opts.check, "check", "", "Run a specific check and print the results. Choose from: process, connections, realtime")
	flag.Parse()

	if opts.version {
		fmt.Println(config.AgentVersion)
		os.Exit(0)
	}

	// Set up a default config before parsing config so we log errors nicely.
	if err := NewLoggerLevelCustom("info"); err != nil {
		panic(err)
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

	// Once config is parsed we can change the log level.
	if err := NewLoggerLevelCustom(cfg.LogLevel); err != nil {
		panic(err)
	}

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

	cl := NewCollector(cfg)
	cl.run()
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
	switch check {
	case "process":
		return printResults(cfg, checks.CollectProcesses, check)
	case "connections":
		return printResults(cfg, checks.CollectConnections, check)
	case "realtime":
		return printResults(cfg, checks.CollectRealTime, check)
	default:
		return fmt.Errorf("invalid check: %s", check)
	}
}

func printResults(cfg *config.AgentConfig, r CheckRunner, check string) error {
	fmt.Printf("-----------------------------\n\n")
	fmt.Printf("\nResults for check %s\n", check)
	fmt.Printf("-----------------------------\n\n")

	msgs, err := r(cfg, 0)
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
