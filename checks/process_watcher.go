package checks

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/DataDog/datadog-process-agent/model"
	log "github.com/cihub/seelog"
)

func watchKey(wp *model.WatchedProcess) string {
	return fmt.Sprintf("%s:%d", wp.Hostname, wp.Pid)
}

type ProcessWatcher struct {
	In      chan *model.WatchedProcess
	Out     chan *model.WatchedResult
	workers int

	// work queue
	results   map[string]*model.WatchedResult
	workQueue chan *model.WatchedProcess

	// FIXME: lock + main select is whack
	sync.Mutex
}

func NewProcessWatcher() *ProcessWatcher {
	pw := &ProcessWatcher{
		In:        make(chan *model.WatchedProcess, 5),
		Out:       make(chan *model.WatchedResult),
		workQueue: make(chan *model.WatchedProcess, 100),
		results:   make(map[string]*model.WatchedResult),
		workers:   5,
	}
	go pw.run()

	for i := 0; i < pw.workers; i++ {
		go pw.startWorker()
	}

	return pw
}

func (pw *ProcessWatcher) run() {
	for {
		select {
		case wp := <-pw.In:
			k := watchKey(wp)
			// Don't push more data until a result is picked up.
			if _, ok := pw.results[k]; ok {
				continue
			}
			pw.workQueue <- wp
		case r := <-pw.Out:
			pw.Lock()
			pw.results[watchKey(r.Process)] = r
			pw.Unlock()
		}
	}
}

func (pw *ProcessWatcher) Results() []*model.WatchedResult {
	pw.Lock()
	defer pw.Unlock()
	results := make([]*model.WatchedResult, 0, len(pw.results))
	for _, wr := range pw.results {
		results = append(results, wr)
	}
	pw.results = make(map[string]*model.WatchedResult)
	return results
}

func (pw *ProcessWatcher) startWorker() {
	for wp := range pw.workQueue {
		output := runProfile(wp)
		pw.Out <- &model.WatchedResult{wp, output, time.Now().Unix()}
	}
}

func runProfile(wp *model.WatchedProcess) string {
	cmd := exec.Command("sudo", "strace", "-p", strconv.Itoa(int(wp.Pid)))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		log.Infof("error tracing pid:%d: %s", wp.Pid, err)
		return ""
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case <-time.After(1 * time.Second):
		// need to kill it with sudo because we started it with sudo.
		// FIXME
		pid := cmd.Process.Pid
		cmd := exec.Command("sudo", "kill", strconv.Itoa(int(pid)))
		if err := cmd.Run(); err != nil {
			log.Errorf("could not kill strace: %s", err)
		}
	case err := <-done:
		if err != nil {
			log.Errorf("process finished without error", err)
		}
	}
	return stderr.String()
}
