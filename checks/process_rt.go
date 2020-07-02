//go:generate goderive .

package checks

import (
	"github.com/StackVista/stackstate-process-agent/cmd/agent/features"
	"github.com/patrickmn/go-cache"
	"time"

	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"
	"github.com/StackVista/stackstate-agent/pkg/util/containers"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/util"
)

// RTProcess is a singleton RTProcessCheck.
var RTProcess = &RTProcessCheck{}

// RTProcessCheck collects numeric statistics about the live processes.
// The instance stores state between checks for calculation of rates and CPU.
type RTProcessCheck struct {
	sysInfo      *model.SystemInfo
	lastCPUTime  cpu.TimesStat
	lastCtrRates map[string]util.ContainerRateMetrics
	lastRun      time.Time

	// Use this as the process cache to calculate rate metrics and drop short-lived processes
	cache *cache.Cache
}

// Init initializes a new RTProcessCheck instance.
func (r *RTProcessCheck) Init(cfg *config.AgentConfig, info *model.SystemInfo) {
	r.sysInfo = info

	r.cache = cache.New(cfg.ProcessCacheDurationMin, cfg.ProcessCacheDurationMin)
}

// Name returns the name of the RTProcessCheck.
func (r *RTProcessCheck) Name() string { return "rtprocess" }

// Endpoint returns the endpoint where this check is submitted.
func (r *RTProcessCheck) Endpoint() string { return "/api/v1/collector" }

// RealTime indicates if this check only runs in real-time mode.
func (r *RTProcessCheck) RealTime() bool { return true }

// Run runs the RTProcessCheck to collect statistics about the running processes.
// On most POSIX systems these statistics are collected from procfs. The bulk
// of this collection is abstracted into the `gopsutil` library.
// Processes are split up into a chunks of at most 100 processes per message to
// limit the message size on intake.
// See agent.proto for the schema of the message and models used.
func (r *RTProcessCheck) Run(cfg *config.AgentConfig, features features.Features, groupID int32) ([]model.MessageBody, error) {
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
	if r.lastRun.IsZero() {
		// fill in the process cache
		for _, fp := range procs {
			PutProcessCache(r.cache, fp)
		}

		r.lastCtrRates = util.ExtractContainerRateMetric(ctrList)
		r.lastCPUTime = cpuTimes[0]
		r.lastRun = time.Now()
		return nil, nil
	}

	chunkedStats := r.fmtProcessStats(cfg, procs, ctrList, cpuTimes[0], r.lastCPUTime, r.lastRun)
	groupSize := len(chunkedStats)
	chunkedCtrStats := fmtContainerStats(ctrList, r.lastCtrRates, r.lastRun, groupSize)
	messages := make([]model.MessageBody, 0, groupSize)
	for i := 0; i < groupSize; i++ {
		messages = append(messages, &model.CollectorRealTime{
			HostName:       cfg.HostName,
			Stats:          chunkedStats[i],
			ContainerStats: chunkedCtrStats[i],
			GroupId:        groupID,
			GroupSize:      int32(groupSize),
			NumCpus:        int32(len(r.sysInfo.Cpus)),
			TotalMemory:    r.sysInfo.TotalMemory,
		})
	}

	// Store the last state for comparison on the next run.
	// Note: not storing the filtered in case there are new processes that haven't had a chance to show up twice.
	r.lastRun = time.Now()
	r.lastCtrRates = util.ExtractContainerRateMetric(ctrList)
	r.lastCPUTime = cpuTimes[0]

	return messages, nil
}

// fmtProcessStats formats and chunks a slice of ProcessStat into chunks.
func (r *RTProcessCheck) fmtProcessStats(
	cfg *config.AgentConfig,
	procs map[int32]*process.FilledProcess,
	ctrList []*containers.Container,
	syst2, syst1 cpu.TimesStat,
	lastRun time.Time,
) [][]*model.ProcessStat {
	cidByPid := make(map[int32]string, len(ctrList))
	for _, c := range ctrList {
		for _, p := range c.Pids {
			cidByPid[p] = c.ID
		}
	}

	// Take all process and format them to the model.Process type
	commonProcesses := make([]*ProcessCommon, 0, cfg.MaxPerMessage)
	processStatMap := make(map[int32]*model.ProcessStat, cfg.MaxPerMessage)
	var totalCPUUsage float32
	var totalMemUsage uint64
	totalCPUUsage = 0.0
	totalMemUsage = 0
	for _, fp := range procs {
		// Check to see if we have this process cached and whether we have observed it for the configured time, otherwise skip
		if processCache, ok := IsProcessCached(r.cache, fp); ok {

			// mapping to a common process type to do sorting
			command := formatCommand(fp)
			memory := formatMemory(fp)
			cpu := formatCPU(fp, fp.CpuTime, processCache.ProcessMetrics.CPUTime, syst2, syst1)
			ioStat := formatIO(fp, processCache.ProcessMetrics.IOStat, lastRun)
			commonProcesses = append(commonProcesses, &ProcessCommon{
				Pid:           fp.Pid,
				Identifier:    createProcessID(fp.Pid, fp.CreateTime),
				FirstObserved: processCache.FirstObserved,
				Command:       command,
				Memory:        memory,
				CPU:           cpu,
				IOStat:        ioStat,
			})

			processStatMap[fp.Pid] = &model.ProcessStat{
				Pid:                    fp.Pid,
				CreateTime:             fp.CreateTime,
				Memory:                 memory,
				Cpu:                    cpu,
				Nice:                   fp.Nice,
				Threads:                fp.NumThreads,
				OpenFdCount:            fp.OpenFdCount,
				ProcessState:           model.ProcessState(model.ProcessState_value[fp.Status]),
				IoStat:                 ioStat,
				VoluntaryCtxSwitches:   uint64(fp.CtxSwitches.Voluntary),
				InvoluntaryCtxSwitches: uint64(fp.CtxSwitches.Involuntary),
				ContainerId:            cidByPid[fp.Pid],
			}

			totalCPUUsage = totalCPUUsage + cpu.TotalPct
			totalMemUsage = totalMemUsage + memory.Rss
		}

		// put it in the cache for the next run
		PutProcessCache(r.cache, fp)
	}

	// Process inclusions
	inclusionProcessesChan := make(chan []*model.ProcessStat)
	inclusionCommonProcesses := make([]*ProcessCommon, len(commonProcesses))
	copy(inclusionCommonProcesses, commonProcesses)
	defer close(inclusionProcessesChan)
	go func() {
		processes := make([]*model.ProcessStat, 0, cfg.MaxPerMessage)
		processes = deriveFmapCommonProcessToProcessStat(mapProcessStat(processStatMap), getProcessInclusions(inclusionCommonProcesses, cfg, totalCPUUsage, totalMemUsage))
		inclusionProcessesChan <- processes
	}()

	// Take the remainingProcesses of the process and strip all processes that should be skipped
	allProcessesChan := make(chan []*model.ProcessStat)
	allCommonProcesses := make([]*ProcessCommon, len(commonProcesses))
	copy(allCommonProcesses, commonProcesses)
	defer close(allProcessesChan)
	go func() {
		processes := make([]*model.ProcessStat, 0, cfg.MaxPerMessage)
		processes = deriveFmapCommonProcessToProcessStat(mapProcessStat(processStatMap), deriveFilterProcesses(keepProcess(cfg), allCommonProcesses))
		allProcessesChan <- processes
	}()

	// sort all, deduplicate and chunk
	processes := append(<-inclusionProcessesChan, <-allProcessesChan...)
	return chunkProcessStats(deriveUniqueProcessStats(deriveSortProcessStats(processes)), cfg.MaxPerMessage, make([][]*model.ProcessStat, 0))
}
