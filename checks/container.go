// +build linux

package checks

import (
	"fmt"
	"github.com/StackVista/stackstate-process-agent/cmd/agent/features"
	"runtime"
	"strings"
	"time"

	"github.com/StackVista/stackstate-agent/pkg/tagger"
	"github.com/StackVista/stackstate-agent/pkg/util/containers"
	log "github.com/cihub/seelog"

	"github.com/StackVista/stackstate-agent/pkg/util/containers/metrics"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/StackVista/stackstate-process-agent/statsd"
	"github.com/StackVista/stackstate-process-agent/util"
)

// Container is a singleton ContainerCheck.
var Container = &ContainerCheck{}

// ContainerCheck is a check that returns container metadata and stats.
type ContainerCheck struct {
	sysInfo   *model.SystemInfo
	lastRates map[string]util.ContainerRateMetrics
	lastRun   time.Time
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
func (c *ContainerCheck) Run(cfg *config.AgentConfig, features features.Features, groupID int32) ([]model.MessageBody, error) {
	start := time.Now()
	ctrList, err := util.GetContainers()
	if err != nil {
		return nil, err
	}

	// End check early if this is our first run.
	if c.lastRates == nil {
		c.lastRates = util.ExtractContainerRateMetric(ctrList)
		c.lastRun = time.Now()
		return nil, nil
	}

	groupSize := len(ctrList) / cfg.MaxPerMessage
	if len(ctrList) != cfg.MaxPerMessage {
		groupSize++
	}
	chunked := chunkedContainers(fmtContainers(cfg, ctrList, c.lastRates, c.lastRun), groupSize)
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

	c.lastRates = util.ExtractContainerRateMetric(ctrList)
	c.lastRun = time.Now()

	statsd.Client.Gauge("datadog.process.containers.host_count", totalContainers, []string{}, 1)
	log.Debugf("collected %d containers in %s", int(totalContainers), time.Now().Sub(start))
	return messages, nil
}

// fmtContainers formats the ctrList
func fmtContainers(
	cfg *config.AgentConfig,
	ctrList []*containers.Container,
	lastRates map[string]util.ContainerRateMetrics,
	lastRun time.Time) []*model.Container {
	containers := make([]*model.Container, 0, len(ctrList))

	for _, ctr := range ctrList {
		lastCtr, ok := lastRates[ctr.ID]
		if !ok {
			// Set to an empty container so rate calculations work and use defaults.
			lastCtr = util.NullContainerRates
		}

		// Just in case the container is found, but refs are nil
		ctr = fillNilContainer(ctr)
		lastCtr = fillNilRates(lastCtr)

		ifStats := ctr.Network.SumInterfaces()
		cpus := runtime.NumCPU()
		sys2, sys1 := ctr.CPU.SystemUsage, lastCtr.CPU.SystemUsage

		// Retrieves metadata tags
		tags, err := tagger.Tag(ctr.EntityID, true)
		if err != nil {
			log.Errorf("unable to retrieve tags for container: %s", err)
			tags = []string{}
		}

		containers = append(containers, &model.Container{
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
			NetRcvdPs:   calculateRate(ifStats.PacketsRcvd, lastCtr.NetworkSum.PacketsRcvd, lastRun),
			NetSentPs:   calculateRate(ifStats.PacketsSent, lastCtr.NetworkSum.PacketsSent, lastRun),
			NetRcvdBps:  calculateRate(ifStats.BytesRcvd, lastCtr.NetworkSum.BytesRcvd, lastRun),
			NetSentBps:  calculateRate(ifStats.BytesSent, lastCtr.NetworkSum.BytesSent, lastRun),
			Started:     ctr.StartedAt,
			Tags:        transformKubernetesTags(tags, cfg.ClusterName),
		})
	}

	return containers
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

func fillNilContainer(ctr *containers.Container) *containers.Container {
	if ctr.CPU == nil {
		ctr.CPU = util.NullContainerRates.CPU
	}
	if ctr.IO == nil {
		ctr.IO = util.NullContainerRates.IO
	}
	if ctr.Network == nil {
		ctr.Network = util.NullContainerRates.Network
	}
	if ctr.Memory == nil {
		ctr.Memory = &metrics.CgroupMemStat{}
	}
	return ctr
}

func fillNilRates(rates util.ContainerRateMetrics) util.ContainerRateMetrics {
	r := &rates
	if rates.CPU == nil {
		r.CPU = util.NullContainerRates.CPU
	}
	if rates.IO == nil {
		r.IO = util.NullContainerRates.IO
	}
	if rates.NetworkSum == nil {
		r.NetworkSum = util.NullContainerRates.NetworkSum
	}
	return *r
}

func transformKubernetesTags(tags []string, clusterName string) []string {
	updatedTags := make([]string, 0, len(tags))

	for _, tag := range tags {
		if strings.HasPrefix(tag, "pod_name:") {
			podName := strings.Split(tag, "pod_name:")[1]
			updatedTags = append(updatedTags, fmt.Sprintf("pod-name:%s", podName))
		} else if strings.HasPrefix(tag, "kube_namespace:") {
			namespace := strings.Split(tag, "kube_namespace:")[1]
			updatedTags = append(updatedTags, fmt.Sprintf("namespace:%s", namespace))
		} else {
			updatedTags = append(updatedTags, tag)
		}
	}

	if clusterName != "" {
		updatedTags = append(updatedTags, fmt.Sprintf("cluster-name:%s", clusterName))
	}

	return updatedTags
}
