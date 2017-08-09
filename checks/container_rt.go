package checks

import (
	"runtime"
	"time"

	"github.com/DataDog/gopsutil/cpu"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/DataDog/datadog-process-agent/util/docker"
)

var RTContainer = &RTContainerCheck{}

// RTContainerCheck collects numeric statistics about live containers.
type RTContainerCheck struct {
	sysInfo        *model.SystemInfo
	lastCPUTime    cpu.TimesStat
	lastContainers []*docker.Container
	lastRun        time.Time
}

// Init initializes a RTContainerCheck instance.
func (r *RTContainerCheck) Init(cfg *config.AgentConfig, sysInfo *model.SystemInfo) {
	r.sysInfo = sysInfo
}

// Name returns the name of the RTContainerCheck.
func (r *RTContainerCheck) Name() string { return "rtcontainer" }

// RealTime indicates if this check only runs in real-time mode.
func (c *RTContainerCheck) RealTime() bool { return false }

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

	groupSize := len(containers) / cfg.ProcLimit
	if len(containers) != cfg.ProcLimit {
		groupSize++
	}
	chunked := fmtContainerStats(containers, r.lastContainers,
		cpuTimes[0], r.lastCPUTime, r.lastRun, groupSize)
	messages := make([]model.MessageBody, 0, groupSize)
	for i := 0; i < groupSize; i++ {
		messages = append(messages, &model.CollectorContainerRealTime{
			HostName:    cfg.HostName,
			Stats:       chunked[i],
			NumCpus:     int32(runtime.NumCPU()),
			TotalMemory: r.sysInfo.TotalMemory,
		})
	}

	r.lastContainers = containers
	r.lastCPUTime = cpuTimes[0]
	r.lastRun = time.Now()

	return messages, nil
}

// fmtContainerStats formats and chunks the containers into a slice of chunks using a specific
// number of chunks. len(result) MUST EQUAL chunks.
func fmtContainerStats(
	containers, lastContainers []*docker.Container,
	syst2, syst1 cpu.TimesStat,
	lastRun time.Time,
	chunks int,
) [][]*model.ContainerStat {
	lastByID := make(map[string]*docker.Container, len(containers))
	for _, c := range lastContainers {
		lastByID[c.ID] = c
	}

	perChunk := (len(containers) / chunks) + 1
	chunked := make([][]*model.ContainerStat, chunks)
	chunk := make([]*model.ContainerStat, 0, perChunk)
	i := 0
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
		chunk = append(chunk, &model.ContainerStat{
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
		if len(chunk) == perChunk {
			chunked[i] = chunk
			chunk = make([]*model.ContainerStat, 0, perChunk)
			i++
		}
	}
	// Add the last chunk if data remains.
	if len(chunk) > 0 {
		chunked[i] = chunk
	}
	return chunked
}
