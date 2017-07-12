package checks

import (
	"time"

	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"

	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/DataDog/datadog-process-agent/util/docker"
)

type RealTimeCheck struct {
	sysInfo        *model.SystemInfo
	lastCPUTime    cpu.TimesStat
	lastProcs      map[int32]*process.FilledProcess
	lastContainers map[int32]*docker.Container
	lastRun        time.Time
}

func NewRealTimeCheck(cfg *config.AgentConfig, sysInfo *model.SystemInfo) *RealTimeCheck {
	return &RealTimeCheck{
		sysInfo:   sysInfo,
		lastProcs: make(map[int32]*process.FilledProcess)}
}

func (r *RealTimeCheck) Name() string { return "real-time" }

func (r *RealTimeCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	cpuTimes, err := cpu.Times(false)
	if err != nil {
		return nil, err
	}
	fps, err := process.AllProcesses()
	if err != nil {
		return nil, err
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

	// Pre-filter the list to get an accurate grou psize.
	filteredFps := make([]*process.FilledProcess, 0, len(fps))
	for _, fp := range fps {
		if !r.skipProcess(cfg, fp) {
			filteredFps = append(filteredFps, fp)
		}
	}
	groupSize := len(filteredFps) / cfg.ProcLimit
	if len(filteredFps) != cfg.ProcLimit {
		groupSize++
	}

	messages := make([]model.MessageBody, 0, groupSize)
	stats := make([]*model.ProcessStat, 0, cfg.ProcLimit)
	for _, fp := range filteredFps {
		if len(stats) >= cfg.ProcLimit {
			messages = append(messages, &model.CollectorRealTime{
				HostName:    cfg.HostName,
				Stats:       stats,
				GroupId:     groupID,
				GroupSize:   int32(groupSize),
				NumCpus:     int32(len(r.sysInfo.Cpus)),
				TotalMemory: r.sysInfo.TotalMemory,
			})
			stats = make([]*model.ProcessStat, 0, cfg.ProcLimit)
		}

		ctr, ok := containerByPID[fp.Pid]
		if !ok {
			ctr = &docker.Container{}
		}
		lastCtr, ok := r.lastContainers[fp.Pid]
		if !ok {
			lastCtr = &docker.Container{}
		}

		stats = append(stats, &model.ProcessStat{
			Pid:          fp.Pid,
			CreateTime:   fp.CreateTime,
			Memory:       formatMemory(fp),
			Cpu:          formatCPU(fp, fp.CpuTime, r.lastProcs[fp.Pid].CpuTime, cpuTimes[0], r.lastCPUTime),
			Nice:         fp.Nice,
			Threads:      fp.NumThreads,
			OpenFdCount:  fp.OpenFdCount,
			ProcessState: model.ProcessState(model.ProcessState_value[fp.Status]),

			// Container-level statistics. These will be duplicated for every process in this container.
			ContainerId:     ctr.ID,
			ContainerState:  model.ContainerState(model.ContainerState_value[ctr.State]),
			ContainerHealth: model.ContainerHealth(model.ContainerHealth_value[ctr.Health]),
			ContainerRbps:   calculateRate(ctr.ReadBytes, lastCtr.ReadBytes, r.lastRun),
			ContainerWbps:   calculateRate(ctr.WriteBytes, lastCtr.WriteBytes, r.lastRun),
		})
	}

	messages = append(messages, &model.CollectorRealTime{
		HostName:    cfg.HostName,
		Stats:       stats,
		GroupId:     groupID,
		GroupSize:   int32(groupSize),
		NumCpus:     int32(len(r.sysInfo.Cpus)),
		TotalMemory: r.sysInfo.TotalMemory,
	})

	// Store the last state for comparison on the next run.
	// Note: not storing the filtered in case there are new processes that haven't had a chance to show up twice.
	r.lastRun = time.Now()
	r.lastProcs = fps
	r.lastContainers = containerByPID
	r.lastCPUTime = cpuTimes[0]

	return messages, nil
}

func (r *RealTimeCheck) skipProcess(cfg *config.AgentConfig, fp *process.FilledProcess) bool {
	if len(fp.Cmdline) == 0 {
		return true
	}
	if config.IsBlacklisted(fp.Cmdline, cfg.Blacklist) {
		return true
	}
	if _, ok := r.lastProcs[fp.Pid]; !ok {
		// Skipping any processes that didn't exist in the previous run.
		// This means short-lived processes (<2s) will never be captured.
		return true
	}
	return false
}

func calculateRate(cur, prev uint64, before time.Time) float32 {
	now := time.Now()
	diff := now.Unix() - before.Unix()
	if before.IsZero() || diff <= 0 {
		return 0
	}
	return float32(cur-prev) / float32(diff)
}
