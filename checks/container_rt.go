// +build docker

package checks

import (
	"runtime"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/docker"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/util/container"
)

// RTContainer is a singleton RTContainerCheck.
var RTContainer = &RTContainerCheck{}

// RTContainerCheck collects numeric statistics about live containers.
type RTContainerCheck struct {
	sysInfo        *model.SystemInfo
	lastContainers []*docker.Container
	lastRun        time.Time
}

// Init initializes a RTContainerCheck instance.
func (r *RTContainerCheck) Init(cfg *config.AgentConfig, sysInfo *model.SystemInfo) {
	r.sysInfo = sysInfo
}

// Name returns the name of the RTContainerCheck.
func (r *RTContainerCheck) Name() string { return "rtcontainer" }

// Endpoint returns the endpoint where this check is submitted.
func (r *RTContainerCheck) Endpoint() string { return "/api/v1/container" }

// RealTime indicates if this check only runs in real-time mode.
func (r *RTContainerCheck) RealTime() bool { return true }

// Run runs the real-time container check getting container-level stats from the Cgroups and Docker APIs.
func (r *RTContainerCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	containers, err := container.GetContainers()
	if err != nil {
		return nil, err
	}

	// End check early if this is our first run.
	if r.lastContainers == nil {
		r.lastContainers = containers
		r.lastRun = time.Now()
		return nil, nil
	}

	groupSize := len(containers) / cfg.MaxPerMessage
	if len(containers) != cfg.MaxPerMessage {
		groupSize++
	}
	chunked := fmtContainerStats(containers, r.lastContainers, r.lastRun, groupSize)
	messages := make([]model.MessageBody, 0, groupSize)
	for i := 0; i < groupSize; i++ {
		messages = append(messages, &model.CollectorContainerRealTime{
			HostName:    cfg.HostName,
			Stats:       chunked[i],
			NumCpus:     int32(runtime.NumCPU()),
			TotalMemory: r.sysInfo.TotalMemory,
			GroupId:     groupID,
			GroupSize:   int32(groupSize),
		})
	}

	r.lastContainers = containers
	r.lastRun = time.Now()

	return messages, nil
}

// fmtContainerStats formats and chunks the containers into a slice of chunks using a specific
// number of chunks. len(result) MUST EQUAL chunks.
func fmtContainerStats(
	containers, lastContainers []*docker.Container,
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

		ifStats := ctr.Network.SumInterfaces()
		lastIfStats := lastCtr.Network.SumInterfaces()
		cpus := runtime.NumCPU()
		sys2, sys1 := ctr.CPU.SystemUsage, lastCtr.CPU.SystemUsage
		chunk = append(chunk, &model.ContainerStat{
			Id:         ctr.ID,
			UserPct:    calculateCtrPct(ctr.CPU.User, lastCtr.CPU.User, sys2, sys1, cpus, lastRun),
			SystemPct:  calculateCtrPct(ctr.CPU.System, lastCtr.CPU.System, sys2, sys1, cpus, lastRun),
			TotalPct:   calculateCtrPct(ctr.CPU.User+ctr.CPU.System, lastCtr.CPU.User+lastCtr.CPU.System, sys2, sys1, cpus, lastRun),
			CpuLimit:   float32(ctr.CPULimit),
			MemRss:     ctr.Memory.RSS,
			MemCache:   ctr.Memory.Cache,
			MemLimit:   ctr.MemLimit,
			Rbps:       calculateRate(ctr.IO.ReadBytes, lastCtr.IO.ReadBytes, lastRun),
			Wbps:       calculateRate(ctr.IO.WriteBytes, lastCtr.IO.WriteBytes, lastRun),
			NetRcvdPs:  calculateRate(ifStats.PacketsRcvd, lastIfStats.PacketsRcvd, lastRun),
			NetSentPs:  calculateRate(ifStats.PacketsSent, lastIfStats.PacketsSent, lastRun),
			NetRcvdBps: calculateRate(ifStats.BytesRcvd, lastIfStats.BytesRcvd, lastRun),
			NetSentBps: calculateRate(ifStats.BytesSent, lastIfStats.BytesSent, lastRun),
			State:      model.ContainerState(model.ContainerState_value[ctr.State]),
			Health:     model.ContainerHealth(model.ContainerHealth_value[ctr.Health]),
			Started:    ctr.StartedAt,
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
