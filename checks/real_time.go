package checks

import (
	"github.com/DataDog/gopsutil/process"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/DataDog/datadog-process-agent/util/docker"
	log "github.com/cihub/seelog"
)

func CollectRealTime(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	var err error
	fps, err := process.AllProcesses(cpuDelta, cfg.Concurrency)
	if err != nil {
		return nil, err
	}
	pids := make([]int32, 0, len(fps))
	for _, fp := range fps {
		pids = append(pids, fp.Pid)
	}
	containerByPID, err := docker.ContainersByPID(pids)
	if err != nil && err != docker.ErrDockerNotAvailable {
		log.Warnf("unable to get docker stats: %s", err)
	}

	info, err := collectSystemInfo(cfg)
	if err != nil {
		return nil, err
	}

	groupSize := len(fps) / cfg.ProcLimit
	if len(fps) != cfg.ProcLimit {
		groupSize++
	}
	messages := make([]model.MessageBody, 0, groupSize)
	stats := make([]*model.ProcessStat, 0, cfg.ProcLimit)
	for _, fp := range fps {
		if len(stats) >= cfg.ProcLimit {
			messages = append(messages, &model.CollectorRealTime{
				HostName:    cfg.HostName,
				Stats:       stats,
				GroupId:     groupID,
				GroupSize:   int32(groupSize),
				NumCpus:     int32(len(info.Cpus)),
				TotalMemory: info.TotalMemory,
			})
			stats = make([]*model.ProcessStat, 0, cfg.ProcLimit)
		}

		stats = append(stats, &model.ProcessStat{
			Pid:         fp.Pid,
			CreateTime:  fp.CreateTime,
			Memory:      formatMemory(fp),
			Cpu:         formatCPU(fp),
			Nice:        fp.Nice,
			State:       0, //model.ProcessStateFromString(fp.Status), TODO
			Threads:     fp.NumThreads,
			ContainerId: cidFromPid(fp.Pid, containerByPID),
			OpenFdCount: fp.OpenFdCount,
		})
	}

	messages = append(messages, &model.CollectorRealTime{
		HostName:    cfg.HostName,
		Stats:       stats,
		GroupId:     groupID,
		GroupSize:   int32(groupSize),
		NumCpus:     int32(len(info.Cpus)),
		TotalMemory: info.TotalMemory,
	})

	return messages, nil
}

func cidFromPid(pid int32, containerMap map[int32]*docker.Container) string {
	if c, ok := containerMap[pid]; ok {
		return c.ID
	}
	return ""
}
