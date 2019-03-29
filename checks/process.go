//go:generate goderive .

package checks

import (
	"sync"
	"time"

	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"
	"github.com/StackVista/stackstate-agent/pkg/util/containers"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/statsd"
	"github.com/StackVista/stackstate-process-agent/util"
	log "github.com/cihub/seelog"
)

// Process is a singleton ProcessCheck.
var Process = &ProcessCheck{}

// ProcessCheck collects full state, including cmdline args and related metadata,
// for live and running processes. The instance will store some state between
// checks that will be used for rates, cpu calculations, etc.
type ProcessCheck struct {
	sync.Mutex

	sysInfo      *model.SystemInfo
	lastCPUTime  cpu.TimesStat
	lastProcs    map[int32]*process.FilledProcess
	lastCtrRates map[string]util.ContainerRateMetrics
	lastRun      time.Time
}

// Init initializes the singleton ProcessCheck.
func (p *ProcessCheck) Init(cfg *config.AgentConfig, info *model.SystemInfo) {
	p.sysInfo = info
}

// Name returns the name of the ProcessCheck.
func (p *ProcessCheck) Name() string { return "process" }

// Endpoint returns the endpoint where this check is submitted.
func (p *ProcessCheck) Endpoint() string { return "/api/v1/collector" }

// RealTime indicates if this check only runs in real-time mode.
func (p *ProcessCheck) RealTime() bool { return false }

// Run runs the ProcessCheck to collect a list of running processes and relevant
// stats for each. On most POSIX systems this will use a mix of procfs and other
// OS-specific APIs to collect this information. The bulk of this collection is
// abstracted into the `gopsutil` library.
// Processes are split up into a chunks of at most 100 processes per message to
// limit the message size on intake.
// See agent.proto for the schema of the message and models used.
func (p *ProcessCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	p.Lock()
	defer p.Unlock()

	start := time.Now()
	cpuTimes, err := cpu.Times(false)
	if err != nil {
		return nil, err
	}
	procs, err := getAllProcesses(cfg)
	if err != nil {
		return nil, err
	}
	ctrList, _ := util.GetContainers()

	// End check early if this is our first run.
	if p.lastProcs == nil {
		p.lastProcs = procs
		p.lastCPUTime = cpuTimes[0]
		p.lastCtrRates = util.ExtractContainerRateMetric(ctrList)
		p.lastRun = time.Now()
		return nil, nil
	}

	chunkedProcs := fmtProcesses(cfg, procs, p.lastProcs,
		ctrList, cpuTimes[0], p.lastCPUTime, p.lastRun)
	// In case we skip every process..
	if len(chunkedProcs) == 0 {
		return nil, nil
	}
	groupSize := len(chunkedProcs)
	chunkedContainers := fmtContainers(ctrList, p.lastCtrRates, p.lastRun, groupSize)
	messages := make([]model.MessageBody, 0, groupSize)
	totalProcs, totalContainers := float64(0), float64(0)
	for i := 0; i < groupSize; i++ {
		totalProcs += float64(len(chunkedProcs[i]))
		totalContainers += float64(len(chunkedContainers[i]))
		messages = append(messages, &model.CollectorProc{
			HostName:   cfg.HostName,
			Info:       p.sysInfo,
			Processes:  chunkedProcs[i],
			Containers: chunkedContainers[i],
			GroupId:    groupID,
			GroupSize:  int32(groupSize),
		})
	}

	// Store the last state for comparison on the next run.
	// Note: not storing the filtered in case there are new processes that haven't had a chance to show up twice.
	p.lastProcs = procs
	p.lastCtrRates = util.ExtractContainerRateMetric(ctrList)
	p.lastCPUTime = cpuTimes[0]
	p.lastRun = time.Now()

	statsd.Client.Gauge("datadog.process.containers.host_count", totalContainers, []string{}, 1)
	statsd.Client.Gauge("datadog.process.processes.host_count", totalProcs, []string{}, 1)
	log.Debugf("collected processes in %s", time.Now().Sub(start))
	return messages, nil
}

func fmtProcesses(
	cfg *config.AgentConfig,
	procs, lastProcs map[int32]*process.FilledProcess,
	ctrList []*containers.Container,
	syst2, syst1 cpu.TimesStat,
	lastRun time.Time,
) [][]*model.Process {
	cidByPid := make(map[int32]string, len(ctrList))
	for _, c := range ctrList {
		for _, p := range c.Pids {
			cidByPid[p] = c.ID
		}
	}

	// Take all process and format them to the model.Process type
	commonProcesses := make([]*ProcessCommon, 0, cfg.MaxPerMessage)
	processMap := make(map[int32]*model.Process, cfg.MaxPerMessage)
	var totalCPUUsage float32
	var totalMemUsage uint64
	totalCPUUsage = 0.0
	totalMemUsage = 0
	for _, fp := range procs {
		// Hide blacklisted args if the Scrubber is enabled
		fp.Cmdline = cfg.Scrubber.ScrubProcessCommand(fp)

		// Skipping any processes that didn't exist in the previous run.
		// This means short-lived processes (<2s) will never be captured.
		if _, ok := pidMissingInLastProcs(fp.Pid, lastProcs); ok {
			continue
		}

		// mapping to a common process type to do sorting
		command := formatCommand(fp)
		memory := formatMemory(fp)
		cpu := formatCPU(fp, fp.CpuTime, lastProcs[fp.Pid].CpuTime, syst2, syst1)
		ioStat := formatIO(fp, lastProcs[fp.Pid].IOStat, lastRun)
		commonProcesses = append(commonProcesses, &ProcessCommon{
			Pid:     fp.Pid,
			Command: command,
			Memory:  memory,
			CPU:     cpu,
			IOStat:  ioStat,
		})

		processMap[fp.Pid] = &model.Process{
			Pid:                    fp.Pid,
			Command:                command,
			User:                   formatUser(fp),
			Memory:                 memory,
			Cpu:                    cpu,
			CreateTime:             fp.CreateTime,
			OpenFdCount:            fp.OpenFdCount,
			State:                  model.ProcessState(model.ProcessState_value[fp.Status]),
			IoStat:                 ioStat,
			VoluntaryCtxSwitches:   uint64(fp.CtxSwitches.Voluntary),
			InvoluntaryCtxSwitches: uint64(fp.CtxSwitches.Involuntary),
			ContainerId:            cidByPid[fp.Pid],
		}

		totalCPUUsage = totalCPUUsage + cpu.TotalPct
		totalMemUsage = totalMemUsage + memory.Rss
	}

	// Process inclusions
	inclusionProcessesChan := make(chan []*model.Process)
	inclusionCommonProcesses := make([]*ProcessCommon, len(commonProcesses))
	copy(inclusionCommonProcesses, commonProcesses)
	defer close(inclusionProcessesChan)
	go func() {
		processes := make([]*model.Process, 0, cfg.MaxPerMessage)
		processes = deriveFmapCommonProcessToProcess(mapProcess(processMap), getProcessInclusions(inclusionCommonProcesses, cfg, totalCPUUsage, totalMemUsage))
		inclusionProcessesChan <- processes
	}()

	// Take the remainingProcesses of the process and strip all processes that should be skipped
	allProcessesChan := make(chan []*model.Process)
	allCommonProcesses := make([]*ProcessCommon, len(commonProcesses))
	copy(allCommonProcesses, commonProcesses)
	defer close(allProcessesChan)
	go func() {
		processes := make([]*model.Process, 0, cfg.MaxPerMessage)
		processes = deriveFmapCommonProcessToProcess(mapProcess(processMap), deriveFilterBlacklistedProcesses(keepProcess(cfg), allCommonProcesses))
		allProcessesChan <- processes
	}()

	// sort all, deduplicate and chunk
	processes := append(<-inclusionProcessesChan, <-allProcessesChan...)
	cfg.Scrubber.IncrementCacheAge()
	return chunkProcesses(deriveUniqueProcesses(deriveSortProcesses(processes)), cfg.MaxPerMessage, make([][]*model.Process, 0))
}
