package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/cihub/seelog"

	"github.com/StackVista/stackstate-agent/pkg/pidfile"
	"github.com/StackVista/stackstate-process-agent/config"
)

// Flag values
var opts struct {
	configPath string

	pidFilePath string
	debug       bool
	version     bool
}

// Version info sourced from build flags
var (
	GoVersion string
	Version   string
	GitCommit string
	GitBranch string
	BuildDate string
)

func main() {
	// Parse flags
	flag.StringVar(&opts.configPath, "config", "/etc/datadog-agent/network-tracer.yaml", "Path to network-tracer config formatted as YAML")
	flag.StringVar(&opts.pidFilePath, "pid", "", "Path to set pidfile for process")
	flag.BoolVar(&opts.version, "version", false, "Print the version and exit")
	flag.Parse()

	// Set up a default config before parsing config so we log errors nicely.
	// The default will be stdout since we can't assume any file is writeable.
	if err := config.NewLoggerLevel("info", "", true); err != nil {
		panic(err)
	}
	defer log.Flush()

	// --version
	if opts.version {
		fmt.Println(versionString())
		os.Exit(0)
	}

	// --pid
	if opts.pidFilePath != "" {
		if err := pidfile.WritePID(opts.pidFilePath); err != nil {
			log.Errorf("Error while writing PID file, exiting: %v", err)
			os.Exit(1)
		}

		log.Infof("pid '%d' written to pid file '%s'", os.Getpid(), opts.pidFilePath)

		defer func() {
			os.Remove(opts.pidFilePath)
		}()
	}

	// Parsing INI and/or YAML config files
	cfg := parseConfig()

	// Exit if network tracer is disabled
	if !cfg.EnableNetworkTracing {
		log.Info("network tracer not enabled. exiting.")
		gracefulExit()
	}

	nettracer, err := CreateNetworkTracer(cfg)
	if err != nil && strings.HasPrefix(err.Error(), ErrTracerUnsupported.Error()) {
		// If tracer is unsupported by this operating system, then exit gracefully
		log.Infof("%s, exiting.", err)
		gracefulExit()
	} else if err != nil {
		log.Criticalf("failed to create network tracer: %s", err)
		os.Exit(1)
	}
	defer nettracer.Close()

	go nettracer.Run()
	log.Infof("network tracer started")

	// Handles signals, which tells us whether we should exit.
	e := make(chan bool)
	go handleSignals(e)
	<-e
}

func gracefulExit() {
	// A sleep is necessary to ensure that supervisor registers this process as "STARTED"
	// If the exit is "too quick", we enter a BACKOFF->FATAL loop even though this is an expected exit
	// http://supervisord.org/subprocess.html#process-states
	time.Sleep(5 * time.Second)
	os.Exit(0)
}

func handleSignals(exit chan bool) {
	sigIn := make(chan os.Signal, 100)
	signal.Notify(sigIn)
	// unix only in all likelihood;  but we don't care.
	for sig := range sigIn {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT:
			log.Criticalf("Caught signal '%s'; terminating.", sig)
			close(exit)
		default:
			log.Warnf("Caught signal %s; continuing/ignoring.", sig)
		}
	}
}

// versionString returns the version information filled in at build time
func versionString() string {
	addString := func(buf *bytes.Buffer, s, arg string) {
		if arg != "" {
			fmt.Fprintf(buf, s, arg)
		}
	}

	var buf bytes.Buffer
	addString(&buf, "Version: %s\n", Version)
	addString(&buf, "Git hash: %s\n", GitCommit)
	addString(&buf, "Git branch: %s\n", GitBranch)
	addString(&buf, "Build date: %s\n", BuildDate)
	addString(&buf, "Go Version: %s\n", GoVersion)
	return buf.String()
}

func parseConfig() *config.AgentConfig {
	yamlConf, err := config.NewYamlIfExists(opts.configPath) // --yamlConfig
	if err != nil {                                          // Will return nil if no Yaml file exists
		log.Criticalf("Error reading YAML formatted config: %s", err)
		os.Exit(1)
	}

	cfg, err := config.NewNetworkAgentConfig(yamlConf)
	if err != nil {
		log.Criticalf("Failed to create agent config: %s", err)
		os.Exit(1)
	}

	return cfg
}
