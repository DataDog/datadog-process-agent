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

	chunked := make([][]*model.Process, 0)
	chunk := make([]*model.Process, 0, cfg.MaxPerMessage)
	for _, fp := range procs {
		if skipProcess(cfg, fp, lastProcs) {
			continue
		}

		// Hide blacklisted args if the Scrubber is enabled
		fp.Cmdline = cfg.Scrubber.ScrubProcessCommand(fp)

		chunk = append(chunk, &model.Process{
			Pid:                    fp.Pid,
			Command:                formatCommand(fp),
			User:                   formatUser(fp),
			Memory:                 formatMemory(fp),
			Cpu:                    formatCPU(fp, fp.CpuTime, lastProcs[fp.Pid].CpuTime, syst2, syst1),
			CreateTime:             fp.CreateTime,
			OpenFdCount:            fp.OpenFdCount,
			State:                  model.ProcessState(model.ProcessState_value[fp.Status]),
			IoStat:                 formatIO(fp, lastProcs[fp.Pid].IOStat, lastRun),
			VoluntaryCtxSwitches:   uint64(fp.CtxSwitches.Voluntary),
			InvoluntaryCtxSwitches: uint64(fp.CtxSwitches.Involuntary),
			ContainerId:            cidByPid[fp.Pid],
		})
		// STS: for now we disable chunking until we support chunked receiving. Otherwise ppid
		// get separated
		if len(chunk) == cfg.MaxPerMessage {
			break
		}
	}
	if len(chunk) > 0 {
		chunked = append(chunked, chunk)
	}
	cfg.Scrubber.IncrementCacheAge()
	return chunked
}

func formatCommand(fp *process.FilledProcess) *model.Command {
	return &model.Command{
		Args:   fp.Cmdline,
		Cwd:    fp.Cwd,
		Root:   "",    // TODO
		OnDisk: false, // TODO
		Ppid:   fp.Ppid,
		Exe:    fp.Exe,
	}
}

func formatIO(fp *process.FilledProcess, lastIO *process.IOCountersStat, before time.Time) *model.IOStat {
	// This will be nill for Mac
	if fp.IOStat == nil {
		return &model.IOStat{}
	}

	diff := time.Now().Unix() - before.Unix()
	if before.IsZero() || diff <= 0 {
		return nil
	}
	// Reading 0 as a counter means the file could not be opened due to permissions. We distinguish this from a real 0 in rates.
	var readRate float32
	readRate = -1
	if fp.IOStat.ReadCount != 0 {
		readRate = calculateRate(fp.IOStat.ReadCount, lastIO.ReadCount, before)
	}
	var writeRate float32
	writeRate = -1
	if fp.IOStat.WriteCount != 0 {
		writeRate = calculateRate(fp.IOStat.WriteCount, lastIO.WriteCount, before)
	}
	var readBytesRate float32
	readBytesRate = -1
	if fp.IOStat.ReadBytes != 0 {
		readBytesRate = calculateRate(fp.IOStat.ReadBytes, lastIO.ReadBytes, before)
	}
	var writeBytesRate float32
	writeBytesRate = -1
	if fp.IOStat.WriteBytes != 0 {
		writeBytesRate = calculateRate(fp.IOStat.WriteBytes, lastIO.WriteBytes, before)
	}
	return &model.IOStat{
		ReadRate:       readRate,
		WriteRate:      writeRate,
		ReadBytesRate:  readBytesRate,
		WriteBytesRate: writeBytesRate,
	}
}

func formatMemory(fp *process.FilledProcess) *model.MemoryStat {
	ms := &model.MemoryStat{
		Rss:  fp.MemInfo.RSS,
		Vms:  fp.MemInfo.VMS,
		Swap: fp.MemInfo.Swap,
	}

	if fp.MemInfoEx != nil {
		ms.Shared = fp.MemInfoEx.Shared
		ms.Text = fp.MemInfoEx.Text
		ms.Lib = fp.MemInfoEx.Lib
		ms.Data = fp.MemInfoEx.Data
		ms.Dirty = fp.MemInfoEx.Dirty
	}
	return ms
}

// skipProcess will skip a given process if it's blacklisted or hasn't existed
// for multiple collections.
func skipProcess(
	cfg *config.AgentConfig,
	fp *process.FilledProcess,
	lastProcs map[int32]*process.FilledProcess,
) bool {
	if len(fp.Cmdline) == 0 {
		return true
	}
	if config.IsBlacklisted(fp.Cmdline, cfg.Blacklist) {
		return true
	}
	if _, ok := lastProcs[fp.Pid]; !ok {
		// Skipping any processes that didn't exist in the previous run.
		// This means short-lived processes (<2s) will never be captured.
		return true
	}
	return false
}

func (p *ProcessCheck) createTimesforPIDs(pids []uint32) map[uint32]int64 {
	p.Lock()
	defer p.Unlock()

	createTimeForPID := make(map[uint32]int64)
	for _, pid := range pids {
		if p, ok := p.lastProcs[int32(pid)]; ok {
			createTimeForPID[pid] = p.CreateTime
		}
	}
	return createTimeForPID
}
