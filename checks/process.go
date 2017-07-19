package checks

import (
	"os"
	"os/user"
	"runtime"
	"strconv"
	"time"
	//"fmt"

	agentpayload "github.com/DataDog/agent-payload/gogen"
	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"
	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/DataDog/datadog-process-agent/util/docker"
	"github.com/DataDog/datadog-process-agent/util/kubernetes"
)

var lastDockerErr string

type ProcessCheck struct {
	kubeUtil       *kubernetes.KubeUtil
	sysInfo        *model.SystemInfo
	lastCPUTime    cpu.TimesStat
	lastProcs      map[int32]*process.FilledProcess
	lastContainers map[int32]*docker.Container
	lastRun        time.Time
}

func NewProcessCheck(cfg *config.AgentConfig, info *model.SystemInfo) *ProcessCheck {
	var err error
	var kubeUtil *kubernetes.KubeUtil
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" && cfg.CollectKubernetesMetadata {
		kubeUtil, err = kubernetes.NewKubeUtil(cfg)
		if err != nil {
			log.Errorf("error initializing kubernetes check, metadata won't be collected: %s", err)
		}
	}

	return &ProcessCheck{
		sysInfo:   info,
		lastProcs: make(map[int32]*process.FilledProcess),
		kubeUtil:  kubeUtil}
}

func (p *ProcessCheck) Name() string { return "process" }

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
	containerByPID, err := docker.ContainersByPID(pids)
	if err != nil && err != docker.ErrDockerNotAvailable && err.Error() != lastDockerErr {
		// Limit docker error logging to once per Agent run to prevent noise when permissions
		// aren't correct.
		log.Warnf("unable to get docker stats: %s", err)
		lastDockerErr = err.Error()
	}
	var kubeMeta *agentpayload.KubeMetadataPayload
	if p.kubeUtil != nil {
		kubeMeta = p.kubeUtil.GetKubernetesMeta(cfg)
	}

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
			Container:   formatContainer(container, lastContainer, p.lastRun),
			OpenFdCount: fp.OpenFdCount,
			State:       model.ProcessState(model.ProcessState_value[fp.Status]),
			IoStat:		 formatIO(fp),
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

func formatIO(fp *process.FilledProcess) *model.IOStat {
	return &model.IOStat{
		ReadCount: fp.IOStat.ReadCount,
		WriteCount: fp.IOStat.WriteCount,
		ReadBytes: fp.IOStat.ReadBytes,
		WriteBytes: fp.IOStat.WriteBytes,
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

func formatContainer(ctr, lastCtr *docker.Container, lastRun time.Time) *model.Container {
	// Container will be nill if the process has no container.
	if ctr == nil {
		return nil
	}
	if lastCtr == nil {
		// Set to an empty container so rate calculations work and use defaults.
		lastCtr = &docker.Container{}
	}

	return &model.Container{
		Type:          ctr.Type,
		Name:          ctr.Name,
		Id:            ctr.ID,
		Image:         ctr.Image,
		CpuLimit:      float32(ctr.CPULimit),
		MemoryLimit:   ctr.MemLimit,
		Created:       ctr.Created,
		State:         model.ContainerState(model.ContainerState_value[ctr.State]),
		Health:        model.ContainerHealth(model.ContainerHealth_value[ctr.Health]),
		ContainerRbps: calculateRate(ctr.ReadBytes, lastCtr.ReadBytes, lastRun),
		ContainerWbps: calculateRate(ctr.WriteBytes, lastCtr.WriteBytes, lastRun),
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
