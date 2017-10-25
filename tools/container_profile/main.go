package main

import (
	"flag"
	"fmt"
	log "github.com/cihub/seelog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/util/docker"
)

func ctrPct(cur, prev uint64, numCPU int, before time.Time) float32 {
	now := time.Now()
	diff := now.Unix() - before.Unix()
	if before.IsZero() || diff <= 0 {
		return 0
	}

	overalPct := float32(cur-prev) / float32(diff)
	// Sometimes we get values that don't make sense, so we clamp to 100%
	if overalPct > 100 {
		overalPct = 100
	}

	// In order to emulate top we multiply utilization by # of CPUs so a busy loop would be 100%.
	return overalPct * float32(numCPU)
}

var opts struct {
	filter       string
	intervalSecs int
}

func main() {
	defer log.Flush()
	flag.StringVar(&opts.filter, "filter", "", "Substring to match container name(s), e.g. 'redis'")
	flag.IntVar(&opts.intervalSecs, "interval", 2, "Seconds between checks")
	flag.Parse()

	if err := config.NewLoggerLevel("info", ""); err != nil {
		log.Errorf("could not initialize logging: %s", err)
		return
	}

	if docker.IsContainerized() {
		if v := os.Getenv("HOST_PROC"); v == "" {
			os.Setenv("HOST_PROC", "/host/proc")
		}
		if v := os.Getenv("HOST_SYS"); v == "" {
			os.Setenv("HOST_SYS", "/host/sys")
		}
	}

	err := docker.InitDockerUtil(&docker.Config{})
	if err != nil {
		log.Errorf("could not initialize docker check: %s", err)
		return
	}

	containers, err := findMatchedContainers()
	if err != nil {
		log.Errorf("error retrieving containers: %s", err)
		return
	}
	log.Infof("Found %d containers matching filter: '%s'", len(containers), opts.filter)

	lastByID := make(map[string]*docker.Container)
	var lastRun time.Time
	for {
		containers, err := findMatchedContainers()
		if err != nil {
			log.Errorf("error retrieving containers: %s", err)
			return
		}
		for _, c := range containers {
			last, ok := lastByID[c.ID]
			if !ok {
				lastByID[c.ID] = c
				lastRun = time.Now()
				continue
			}

			cpus := runtime.NumCPU()
			fmt.Printf("-------------\nContainer: %s/%s\n", c.Name, c.Image)
			fmt.Printf("Last Run: %s\n", lastRun)
			fmt.Printf("CPU - cores: %d, ut: %d, st: %d, total: %d\n", cpus, c.CPU.User, c.CPU.System, c.CPU.User+c.CPU.System)
			fmt.Printf("Sys: %1.2f%%\n", ctrPct(c.CPU.System, last.CPU.System, cpus, lastRun))
			fmt.Printf("User: %1.2f%%\n", ctrPct(c.CPU.User, last.CPU.User, cpus, lastRun))
			fmt.Printf("Total: %1.2f%%\n", ctrPct(c.CPU.System+c.CPU.User, last.CPU.System+last.CPU.User, cpus, lastRun))

			// Set last values for diffs
			lastByID[c.ID] = c
			lastRun = time.Now()
		}

		time.Sleep(time.Duration(opts.intervalSecs) * time.Second)
	}
}

func findMatchedContainers() ([]*docker.Container, error) {
	containers, err := docker.AllContainers()
	if err != nil {
		return nil, err
	}

	matched := make([]*docker.Container, 0)
	for _, c := range containers {
		if strings.Contains(c.Name, opts.filter) {
			matched = append(matched, c)
		}
	}
	return matched, nil
}
