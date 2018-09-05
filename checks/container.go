// +build linux

package checks

import (
	"runtime"
	"time"

	"github.com/DataDog/datadog-agent/pkg/tagger"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/model"
	"github.com/DataDog/datadog-process-agent/statsd"
	"github.com/DataDog/datadog-process-agent/util"
)

// Container is a singleton ContainerCheck.
var Container = &ContainerCheck{}

// ContainerCheck is a check that returns container metadata and stats.
type ContainerCheck struct {
	sysInfo        *model.SystemInfo
	lastContainers []*containers.Container
	lastRun        time.Time
}

// Init initializes a ContainerCheck instance.
func (c *ContainerCheck) Init(cfg *config.AgentConfig, info *model.SystemInfo) {
	c.sysInfo = info
}

// Name returns the name of the ProcessCheck.
func (c *ContainerCheck) Name() string { return "container" }

// Endpoint returns the endpoint where this check is submitted.
func (c *ContainerCheck) Endpoint() string { return "/api/v1/container" }

// RealTime indicates if this check only runs in real-time mode.
func (c *ContainerCheck) RealTime() bool { return false }

// Run runs the ContainerCheck to collect a list of running ctrList and the
// stats for each container.
func (c *ContainerCheck) Run(cfg *config.AgentConfig, groupID int32) ([]model.MessageBody, error) {
	start := time.Now()
	ctrList, err := util.GetContainers()
	if err != nil {
		return nil, err
	}

	// End check early if this is our first run.
	if c.lastContainers == nil {
		c.lastContainers = ctrList
		c.lastRun = time.Now()
		return nil, nil
	}

	groupSize := len(ctrList) / cfg.MaxPerMessage
	if len(ctrList) != cfg.MaxPerMessage {
		groupSize++
	}
	chunked := fmtContainers(ctrList, c.lastContainers, c.lastRun, groupSize)
	messages := make([]model.MessageBody, 0, groupSize)
	totalContainers := float64(0)
	for i := 0; i < groupSize; i++ {
		totalContainers += float64(len(chunked[i]))
		messages = append(messages, &model.CollectorContainer{
			HostName:   cfg.HostName,
			Info:       c.sysInfo,
			Containers: chunked[i],
			GroupId:    groupID,
			GroupSize:  int32(groupSize),
		})
	}

	c.lastContainers = ctrList
	c.lastRun = time.Now()

	statsd.Client.Gauge("datadog.process.containers.host_count", totalContainers, []string{}, 1)
	log.Debugf("collected %d containers in %s", int(totalContainers), time.Now().Sub(start))
	return messages, nil
}

// fmtContainers formats and chunks the ctrList into a slice of chunks using a specific
// number of chunks. len(result) MUST EQUAL chunks.
func fmtContainers(
	ctrList, lastContainers []*containers.Container,
	lastRun time.Time,
	chunks int,
) [][]*model.Container {
	lastByID := make(map[string]*containers.Container, len(ctrList))
	for _, c := range lastContainers {
		lastByID[c.ID] = c
	}

	perChunk := (len(ctrList) / chunks) + 1
	chunked := make([][]*model.Container, chunks)
	chunk := make([]*model.Container, 0, perChunk)
	i := 0
	for _, ctr := range ctrList {
		lastCtr, ok := lastByID[ctr.ID]
		if !ok {
			// Set to an empty container so rate calculations work and use defaults.
			lastCtr = util.NullContainer
		}

		// Just in case the container is found, but refs are nil
		fillNilContainers(ctr, lastCtr)

		ifStats := ctr.Network.SumInterfaces()
		lastIfStats := lastCtr.Network.SumInterfaces()
		cpus := runtime.NumCPU()
		sys2, sys1 := ctr.CPU.SystemUsage, lastCtr.CPU.SystemUsage

		// Retrieves metadata tags
		tags, err := tagger.Tag(ctr.EntityID, true)
		if err != nil {
			log.Errorf("unable to retrieve tags for container: %s", err)
			tags = []string{}
		}

		chunk = append(chunk, &model.Container{
			Id:          ctr.ID,
			Type:        ctr.Type,
			CpuLimit:    float32(ctr.CPULimit),
			UserPct:     calculateCtrPct(ctr.CPU.User, lastCtr.CPU.User, sys2, sys1, cpus, lastRun),
			SystemPct:   calculateCtrPct(ctr.CPU.System, lastCtr.CPU.System, sys2, sys1, cpus, lastRun),
			TotalPct:    calculateCtrPct(ctr.CPU.User+ctr.CPU.System, lastCtr.CPU.User+lastCtr.CPU.System, sys2, sys1, cpus, lastRun),
			MemoryLimit: ctr.MemLimit,
			MemRss:      ctr.Memory.RSS,
			MemCache:    ctr.Memory.Cache,
			Created:     ctr.Created,
			State:       model.ContainerState(model.ContainerState_value[ctr.State]),
			Health:      model.ContainerHealth(model.ContainerHealth_value[ctr.Health]),
			Rbps:        calculateRate(ctr.IO.ReadBytes, lastCtr.IO.ReadBytes, lastRun),
			Wbps:        calculateRate(ctr.IO.WriteBytes, lastCtr.IO.WriteBytes, lastRun),
			NetRcvdPs:   calculateRate(ifStats.PacketsRcvd, lastIfStats.PacketsRcvd, lastRun),
			NetSentPs:   calculateRate(ifStats.PacketsSent, lastIfStats.PacketsSent, lastRun),
			NetRcvdBps:  calculateRate(ifStats.BytesRcvd, lastIfStats.BytesRcvd, lastRun),
			NetSentBps:  calculateRate(ifStats.BytesSent, lastIfStats.BytesSent, lastRun),
			Started:     ctr.StartedAt,
			Tags:        tags,
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

func calculateCtrPct(cur, prev, sys2, sys1 uint64, numCPU int, before time.Time) float32 {
	now := time.Now()
	diff := now.Unix() - before.Unix()
	if before.IsZero() || diff <= 0 {
		return 0
	}

	// If we have system usage values then we need to calculate against those.
	// XXX: Right now this only applies to ECS collection
	if sys1 > 0 && sys2 > 0 {
		cpuDelta := float32(cur - prev)
		sysDelta := float32(sys2 - sys1)
		return (cpuDelta / sysDelta) * float32(numCPU) * 100
	}
	return float32(cur-prev) / float32(diff)
}

func fillNilContainers(ctrs ...*containers.Container) {
	for _, c := range ctrs {
		if c.CPU == nil {
			c.CPU = util.NullContainer.CPU
		}
		if c.Memory == nil {
			c.Memory = util.NullContainer.Memory
		}
		if c.IO == nil {
			c.IO = util.NullContainer.IO
		}
		if c.Network == nil {
			c.Network = util.NullContainer.Network
		}
	}
}
