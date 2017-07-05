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
)

const (
	// cpuDelta is the amount of time spent between CPU timing checks.
	cpuDelta = 1 * time.Second
)

var lastDockerErr string

type ProcessCheck struct {
	lastCPUTime cpu.TimesStat
	lastProcs   map[int32]*process.FilledProcess
}

func (p *ProcessCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	start := time.Now()
	cpuTimes, err := cpu.Times(false)
	if err != nil {
		return nil, err
	}
	fps, err := process.AllProcesses(cpuDelta, cfg.Concurrency)
	if err != nil {
		return nil, err
	}

	// End check early if this is our first run.
	if p.lastProcs == nil {
		p.lastProcs = fps
		p.lastCPUTime = cpuTimes[0]
		return nil, nil
	}

	pids := make([]int32, 0, len(fps))
	for _, fp := range fps {
		pids = append(pids, fp.Pid)
	}
	containerByPID, err := docker.ContainersByPID(pids)
	if err != nil && err != docker.ErrDockerNotAvailable && err.Error() != lastDockerErr {
		// Limit docker error logging to once per Agent run to prevent noise when permissions
		// aren't correct.
		log.Warnf("unable to get docker stats: %s", err)
		lastDockerErr = err.Error()
	}

	info, err := collectSystemInfo(cfg)
	if err != nil {
		return nil, err
	}

	// Pre-filter the list to get an accurate grou psize.
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
		container, _ := containerByPID[fp.Pid]

		if len(procs) >= cfg.ProcLimit {
			messages = append(messages, &model.CollectorProc{
				HostName:  cfg.HostName,
				Processes: procs,
				Info:      info,
				GroupId:   groupID,
				GroupSize: int32(groupSize),
			})
			procs = make([]*model.Process, 0, cfg.ProcLimit)
		}

		procs = append(procs, &model.Process{
			Pid:         fp.Pid,
			Command:     formatCommand(fp),
			User:        formatUser(fp),
			Memory:      formatMemory(fp),
			Cpu:         formatCPU(fp, fp.CpuTime, p.lastProcs[fp.Pid].CpuTime, cpuTimes[0], p.lastCPUTime),
			CreateTime:  fp.CreateTime,
			Container:   formatContainer(container),
			OpenFdCount: fp.OpenFdCount,
		})
	}

	messages = append(messages, &model.CollectorProc{
		HostName:  cfg.HostName,
		Processes: procs,
		Info:      info,
		GroupId:   groupID,
		GroupSize: int32(groupSize),
		// FIXME: We should not send this in every payload. Long-term the container
		// ID should be enough context to resolve this metadata on the backend.
		Kubernetes: GetKubernetesMeta(),
	})

	// Store the last state for comparison on the next run.
	// Note: not storing the filtered in case there are new processes that haven't had a chance to show up twice.
	p.lastProcs = fps
	p.lastCPUTime = cpuTimes[0]

	log.Infof("collected processes in %s", time.Now().Sub(start))
	return messages, nil
}

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
		State:  fp.Status,
		Cwd:    fp.Cwd,
		Root:   "",    // TODO
		OnDisk: false, // TODO
		Ppid:   fp.Ppid,
		Pgroup: fp.Pgrp,
		Exe:    fp.Exe,
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

func formatContainer(container *docker.Container) *model.Container {
	// Container will be nill if the process has no container.
	if container == nil {
		return nil
	}
	return &model.Container{
		Type:        container.Type,
		Name:        container.Name,
		Id:          container.ID,
		Image:       container.Image,
		CpuLimit:    float32(container.CPULimit),
		MemoryLimit: container.MemLimit,
		Status:      container.Status,
	}
}

func calculatePct(deltaProc, deltaTime, numCPU float64) float32 {
	if deltaTime == 0 {
		return 0
	}

	// Calculates utilization split across all CPUs. A busy-loop process
	// on a 2-CPU-core system would be reported as 50% instead of 100%.
	overalPct := (deltaProc / deltaTime) * 100

	// In order to emulate top we multiply utilization by # of CPUs so a busy loop would be 100%.
	return float32(overalPct * numCPU)
}
