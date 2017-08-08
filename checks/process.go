package checks

import (
	"os/user"
	"runtime"
	"strconv"
	"time"

	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"
	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/DataDog/datadog-process-agent/util/docker"
	"github.com/DataDog/datadog-process-agent/util/ecs"
	"github.com/DataDog/datadog-process-agent/util/kubernetes"
)

var Process = &ProcessCheck{}

// ProcessCheck collects full state, including cmdline args and related metadata,
// for live and running processes. The instance will store some state between
// checks that will be used for rates, cpu calculations, etc.
type ProcessCheck struct {
	sysInfo        *model.SystemInfo
	lastCPUTime    cpu.TimesStat
	lastProcs      map[int32]*process.FilledProcess
	lastContainers map[int32]*docker.Container
	lastRun        time.Time
}

// NewProcessCheck returns a new ProcessCheck initialized with a connection to
// Kubernetes (if appliable) and other zeoes-out information.
func (p *ProcessCheck) Init(cfg *config.AgentConfig, info *model.SystemInfo) {
	p.sysInfo = info
	p.lastProcs = make(map[int32]*process.FilledProcess)
}

// Name returns the name of the ProcessCheck.
func (p *ProcessCheck) Name() string { return "process" }

// RealTime indicates if this check only runs in real-time mode.
func (c *ProcessCheck) RealTime() bool { return false }

// Run runs the ProcessCheck to collect a list of running processes and relevant
// stats for each. On most POSIX systems this will use a mix of procfs and other
// OS-specific APIs to collect this information. The bulk of this collection is
// abstracted into the `gopsutil` library.
// Processes are split up into a chunks of at most 100 processes per message to
// limit the message size on intake.
// See agent.proto for the schema of the message and models used.
func (p *ProcessCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	start := time.Now()
	cpuTimes, err := cpu.Times(false)
	if err != nil {
		return nil, err
	}
	fps, err := process.AllProcesses()
	if err != nil {
		return nil, err
	}
	// End check early if this is our first run.
	if p.lastProcs == nil {
		p.lastProcs = fps
		p.lastCPUTime = cpuTimes[0]
		return nil, nil
	}

	// Pull in container metadata, where available.
	pids := make([]int32, 0, len(fps))
	for _, fp := range fps {
		pids = append(pids, fp.Pid)
	}
	containerByPID := docker.ContainersForPIDs(pids)
	ecsMeta := ecs.GetMetadata()
	kubeMeta := kubernetes.GetMetadata()

	// Pre-filter the list to get an accurate group size.
	filteredFps := make([]*process.FilledProcess, 0, len(fps))
	for _, fp := range fps {
		if !p.skipProcess(cfg, fp) {
			filteredFps = append(filteredFps, fp)
		}
	}
	groupSize := len(filteredFps) / cfg.ProcLimit
	if len(filteredFps) != cfg.ProcLimit {
		groupSize++
	}

	messages := make([]model.MessageBody, 0, groupSize)
	procs := make([]*model.Process, 0, cfg.ProcLimit)
	for _, fp := range filteredFps {
		if len(procs) >= cfg.ProcLimit {
			messages = append(messages, &model.CollectorProc{
				HostName:   cfg.HostName,
				Processes:  procs,
				Info:       p.sysInfo,
				GroupId:    groupID,
				GroupSize:  int32(groupSize),
				Kubernetes: kubeMeta,
				Ecs:        ecsMeta,
			})
			procs = make([]*model.Process, 0, cfg.ProcLimit)
		}

		container, _ := containerByPID[fp.Pid]
		lastContainer, _ := p.lastContainers[fp.Pid]
		procs = append(procs, &model.Process{
			Pid:         fp.Pid,
			Command:     formatCommand(fp),
			User:        formatUser(fp),
			Memory:      formatMemory(fp),
			Cpu:         formatCPU(fp, fp.CpuTime, p.lastProcs[fp.Pid].CpuTime, cpuTimes[0], p.lastCPUTime),
			CreateTime:  fp.CreateTime,
			Container:   formatContainer(container, lastContainer, cpuTimes[0], p.lastCPUTime, p.lastRun),
			OpenFdCount: fp.OpenFdCount,
			State:       model.ProcessState(model.ProcessState_value[fp.Status]),
			IoStat:      formatIO(fp, p.lastProcs[fp.Pid].IOStat, p.lastRun),
		})
	}

	messages = append(messages, &model.CollectorProc{
		HostName:  cfg.HostName,
		Processes: procs,
		Info:      p.sysInfo,
		GroupId:   groupID,
		GroupSize: int32(groupSize),
		// FIXME: We should not send this in every payload. Long-term the container
		// ID should be enough context to resolve this metadata on the backend.
		Kubernetes: kubeMeta,
		Ecs:        ecsMeta,
	})

	// Store the last state for comparison on the next run.
	// Note: not storing the filtered in case there are new processes that haven't had a chance to show up twice.
	p.lastProcs = fps
	p.lastContainers = containerByPID
	p.lastCPUTime = cpuTimes[0]
	p.lastRun = time.Now()

	log.Infof("collected processes in %s", time.Now().Sub(start))
	return messages, nil
}

// skipProcess will skip a given process if it's blacklisted or hasn't existed
// for multiple collections.
func (p *ProcessCheck) skipProcess(cfg *config.AgentConfig, fp *process.FilledProcess) bool {
	if len(fp.Cmdline) == 0 {
		return true
	}
	if config.IsBlacklisted(fp.Cmdline, cfg.Blacklist) {
		return true
	}
	if _, ok := p.lastProcs[fp.Pid]; !ok {
		// Skipping any processes that didn't exist in the previous run.
		// This means short-lived processes (<2s) will never be captured.
		return true
	}
	return false
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

func formatUser(fp *process.FilledProcess) *model.ProcessUser {
	var username string
	var uid, gid int32
	if len(fp.Uids) > 0 {
		u, err := user.LookupId(strconv.Itoa(int(fp.Uids[0])))
		if err == nil {
			username = u.Username
		}
		uid = int32(fp.Uids[0])
	}
	if len(fp.Gids) > 0 {
		gid = int32(fp.Gids[0])
	}

	return &model.ProcessUser{
		Name: username,
		Uid:  uid,
		Gid:  gid,
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

func formatCPU(fp *process.FilledProcess, t2, t1, syst2, syst1 cpu.TimesStat) *model.CPUStat {
	numCPU := float64(runtime.NumCPU())
	deltaSys := syst2.Total() - syst1.Total()
	return &model.CPUStat{
		LastCpu:    t2.CPU,
		TotalPct:   calculatePct((t2.User-t1.User)+(t2.System-t1.System), deltaSys, numCPU),
		UserPct:    calculatePct(t2.User-t1.User, deltaSys, numCPU),
		SystemPct:  calculatePct(t2.System-t1.System, deltaSys, numCPU),
		NumThreads: fp.NumThreads,
		Cpus:       []*model.SingleCPUStat{},
		Nice:       fp.Nice,
		UserTime:   int64(t2.User),
		SystemTime: int64(t2.System),
	}
}

func calculatePct(deltaProc, deltaTime, numCPU float64) float32 {
	if deltaTime == 0 {
		return 0
	}

	// Calculates utilization split across all CPUs. A busy-loop process
	// on a 2-CPU-core system would be reported as 50% instead of 100%.
	overalPct := (deltaProc / deltaTime) * 100

	// Sometimes we get values that don't make sense, so we clamp to 100%
	if overalPct > 100 {
		overalPct = 100
	}

	// In order to emulate top we multiply utilization by # of CPUs so a busy loop would be 100%.
	return float32(overalPct * numCPU)
}
