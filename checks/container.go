package checks

import (
	"runtime"
	"time"

	"github.com/DataDog/gopsutil/cpu"
	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/DataDog/datadog-process-agent/util/docker"
	"github.com/DataDog/datadog-process-agent/util/ecs"
	"github.com/DataDog/datadog-process-agent/util/kubernetes"
)

const nanoSecondsPerSecond uint64 = 10e9

var Container = &ContainerCheck{}

// ContainerCheck is a check that returns container metadata and stats.
type ContainerCheck struct {
	sysInfo        *model.SystemInfo
	lastCPUTime    cpu.TimesStat
	lastContainers []*docker.Container
	lastRun        time.Time
}

// Init initializes a ContainerCheck instance.
func (c *ContainerCheck) Init(cfg *config.AgentConfig, info *model.SystemInfo) {
	c.sysInfo = info
}

// Name returns the name of the ProcessCheck.
func (c *ContainerCheck) Name() string { return "container" }

// RealTime indicates if this check only runs in real-time mode.
func (c *ContainerCheck) RealTime() bool { return false }

// Run runs the ContainerCheck to collect a list of running containers and the
// stats for each container.
func (c *ContainerCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	start := time.Now()
	cpuTimes, err := cpu.Times(false)
	if err != nil {
		return nil, err
	}
	containers, err := docker.AllContainers()
	if err != nil {
		return nil, err
	}

	// End check early if this is our first run.
	if c.lastContainers == nil {
		c.lastContainers = containers
		c.lastCPUTime = cpuTimes[0]
		c.lastRun = time.Now()
		return nil, nil
	}

	// Fetch orchestrator metadata once per check.
	ecsMeta := ecs.GetMetadata()
	kubeMeta := kubernetes.GetMetadata()

	groupSize := len(containers) / cfg.ProcLimit
	if len(containers) != cfg.ProcLimit {
		groupSize++
	}
	chunked := fmtContainers(containers, c.lastContainers,
		cpuTimes[0], c.lastCPUTime, c.lastRun, groupSize)
	messages := make([]model.MessageBody, 0, groupSize)
	for i := 0; i < groupSize; i++ {
		messages = append(messages, &model.CollectorContainer{
			HostName:   cfg.HostName,
			Info:       c.sysInfo,
			Containers: chunked[i],
			GroupId:    groupID,
			GroupSize:  int32(groupSize),
			Kubernetes: kubeMeta,
			Ecs:        ecsMeta,
		})
	}

	c.lastCPUTime = cpuTimes[0]
	c.lastContainers = containers
	c.lastRun = time.Now()

	log.Infof("collected containers in %s", time.Now().Sub(start))
	return messages, nil
}

// fmtContainers formats and chunks the containers into a slice of chunks using a specific
// number of chunks. len(result) MUST EQUAL chunks.
func fmtContainers(
	containers, lastContainers []*docker.Container,
	syst2, syst1 cpu.TimesStat,
	lastRun time.Time,
	chunks int,
) [][]*model.Container {
	lastByID := make(map[string]*docker.Container, len(containers))
	for _, c := range lastContainers {
		lastByID[c.ID] = c
	}

	perChunk := (len(containers) / chunks) + 1
	chunked := make([][]*model.Container, chunks)
	chunk := make([]*model.Container, 0, perChunk)
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
		chunk = append(chunk, &model.Container{
			Type:        ctr.Type,
			Name:        ctr.Name,
			Id:          ctr.ID,
			Image:       ctr.Image,
			CpuLimit:    float32(ctr.CPU.Limit),
			UserPct:     calculateCtrPct(deltaUser, deltaTime, numCPU),
			SystemPct:   calculateCtrPct(deltaSys, deltaTime, numCPU),
			TotalPct:    calculateCtrPct(deltaUser+deltaSys, deltaTime, numCPU),
			MemoryLimit: ctr.Memory.MemLimitInBytes,
			Created:     ctr.Created,
			State:       model.ContainerState(model.ContainerState_value[ctr.State]),
			Health:      model.ContainerHealth(model.ContainerHealth_value[ctr.Health]),
			Rbps:        calculateRate(ctr.IO.ReadBytes, lastCtr.IO.ReadBytes, lastRun),
			Wbps:        calculateRate(ctr.IO.WriteBytes, lastCtr.IO.WriteBytes, lastRun),
			NetRcvdPs:   calculateRate(ctr.Network.PacketsRcvd, lastCtr.Network.PacketsRcvd, lastRun),
			NetSentPs:   calculateRate(ctr.Network.PacketsSent, lastCtr.Network.PacketsSent, lastRun),
			NetRcvdBps:  calculateRate(ctr.Network.BytesRcvd, lastCtr.Network.BytesRcvd, lastRun),
			NetSentBps:  calculateRate(ctr.Network.BytesSent, lastCtr.Network.BytesSent, lastRun),
		})

		if len(chunk) == perChunk {
			chunked[i] = chunk
			chunk = make([]*model.Container, 0, perChunk)
			i++
		}
	}
	if len(chunk) > 0 {
		chunked[i] = chunk
	}
	return chunked
}

func calculateCtrPct(deltaProc, deltaTime uint64, numCPU float64) float32 {
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
	return float32(overalPct * uint64(numCPU))
}
