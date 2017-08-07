package checks

import (
	"runtime"
	"time"

	"github.com/DataDog/gopsutil/cpu"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/DataDog/datadog-process-agent/util/docker"
)

// RTContainerCheck collects numeric statistics about live containers.
type RTContainerCheck struct {
	sysInfo        *model.SystemInfo
	lastCPUTime    cpu.TimesStat
	lastContainers []*docker.Container
	lastRun        time.Time
}

// NewRTContainerCheck returns a new RTContainerCheck.
func NewRTContainerCheck(cfg *config.AgentConfig, sysInfo *model.SystemInfo) *RTContainerCheck {
	return &RTContainerCheck{sysInfo: sysInfo}
}

// Name returns the name of the RTContainerCheck.
func (r *RTContainerCheck) Name() string { return "rt-container" }

func (r *RTContainerCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	cpuTimes, err := cpu.Times(false)
	if err != nil {
		return nil, err
	}
	containers, err := docker.AllContainers()
	if err != nil {
		return nil, err
	}

	// End check early if this is our first run.
	if r.lastContainers == nil {
		r.lastContainers = containers
		r.lastCPUTime = cpuTimes[0]
		r.lastRun = time.Now()
		return nil, nil
	}

	formatted := fmtContainerStats(containers, r.lastContainers,
		cpuTimes[0], r.lastCPUTime, r.lastRun)
	groupSize := len(formatted) / cfg.ProcLimit
	if len(formatted) != cfg.ProcLimit {
		groupSize++
	}

	messages := make([]model.MessageBody, 0, groupSize)
	for i := 0; i < groupSize; i++ {
		end := groupSize * (i + 1)
		if end > len(formatted) {
			end = len(formatted)
		}
		messages = append(messages, &model.CollectorContainerRealTime{
			HostName:    cfg.HostName,
			Stats:       formatted[i*groupSize : end],
			NumCpus:     int32(runtime.NumCPU()),
			TotalMemory: r.sysInfo.TotalMemory,
		})
	}

	r.lastContainers = containers
	r.lastCPUTime = cpuTimes[0]
	r.lastRun = time.Now()

	return messages, nil
}

func fmtContainerStats(
	containers, lastContainers []*docker.Container,
	syst2, syst1 cpu.TimesStat,
	lastRun time.Time,
) []*model.ContainerStat {
	lastByID := make(map[string]*docker.Container, len(containers))
	for _, c := range lastContainers {
		lastByID[c.ID] = c
	}

	stats := make([]*model.ContainerStat, 0, len(containers))
	for _, ctr := range containers {
		lastCtr, ok := lastByID[ctr.ID]
		if !ok {
			// Set to an empty container so rate calculations work and use defaults.
			lastCtr = docker.NullContainer
		}

		numCPU := float64(runtime.NumCPU())
		deltaUser := ctr.CPU.User - lastCtr.CPU.User
		deltaSys := ctr.CPU.System - lastCtr.CPU.System
		// User and Sys times are in nanoseconds for cgroups, so we must adjust our system time.
		deltaTime := uint64(syst2.Total()-syst1.Total()) * nanoSecondsPerSecond
		stats = append(stats, &model.ContainerStat{
			Id:         ctr.ID,
			UserPct:    calculateCtrPct(deltaUser, deltaTime, numCPU),
			SystemPct:  calculateCtrPct(deltaSys, deltaTime, numCPU),
			TotalPct:   calculateCtrPct(deltaUser+deltaSys, deltaTime, numCPU),
			CpuLimit:   float32(ctr.CPU.Limit),
			MemRss:     ctr.Memory.RSS,
			MemCache:   ctr.Memory.Cache,
			MemLimit:   ctr.Memory.MemLimitInBytes,
			Rbps:       calculateRate(ctr.IO.ReadBytes, lastCtr.IO.ReadBytes, lastRun),
			Wbps:       calculateRate(ctr.IO.WriteBytes, lastCtr.IO.WriteBytes, lastRun),
			NetRcvdPs:  calculateRate(ctr.Network.PacketsRcvd, lastCtr.Network.PacketsRcvd, lastRun),
			NetSentPs:  calculateRate(ctr.Network.PacketsSent, lastCtr.Network.PacketsSent, lastRun),
			NetRcvdBps: calculateRate(ctr.Network.BytesRcvd, lastCtr.Network.BytesRcvd, lastRun),
			NetSentBps: calculateRate(ctr.Network.BytesSent, lastCtr.Network.BytesSent, lastRun),
		})
	}
	return stats
}
