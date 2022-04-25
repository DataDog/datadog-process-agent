//go:build linux
// +build linux

package checks

import (
	"fmt"
	"github.com/StackVista/stackstate-agent/pkg/aggregator"
	"github.com/StackVista/stackstate-agent/pkg/telemetry"
	"runtime"
	"strings"
	"time"

	"github.com/StackVista/stackstate-agent/pkg/tagger/collectors"
	"github.com/StackVista/stackstate-process-agent/cmd/agent/features"

	"github.com/StackVista/stackstate-agent/pkg/tagger"
	"github.com/StackVista/stackstate-agent/pkg/util/containers"
	log "github.com/cihub/seelog"

	"github.com/StackVista/stackstate-agent/pkg/process/util"
	"github.com/StackVista/stackstate-agent/pkg/util/containers/metrics"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
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

// Sender returns an instance of the check sender
func (c *ContainerCheck) Sender() aggregator.Sender {
	return GetSender(c.Name())
}

// Run runs the ContainerCheck to collect a list of running ctrList and the
// stats for each container.
func (c *ContainerCheck) Run(cfg *config.AgentConfig, featureSet features.Features, groupID int32, currentTime time.Time) (*CheckResult, error) {
	start := time.Now()
	ctrList, err := util.GetContainers()
	if err != nil {
		return nil, err
	}

	s, err := aggregator.GetSender("process-agent")
	if err != nil {
		_ = log.Error("No default sender available: ", err)
	}
	defer s.Commit()

	// End check early if this is our first run.
	if c.lastRates == nil {
		c.lastRates = util.ExtractContainerRateMetric(ctrList)
		c.lastRun = time.Now()
		return nil, nil
	}

	groupCount := len(ctrList) / cfg.MaxPerMessage
	if len(ctrList) != cfg.MaxPerMessage {
		groupCount++
	}
	useMultiMetrics := featureSet.FeatureEnabled(features.UpgradeToMultiMetrics)

	cnts, metrics := fmtContainers(cfg, ctrList, c.lastRates, c.lastRun, useMultiMetrics)
	chunked := chunkedContainers(cnts, groupCount)

	messages := make([]model.MessageBody, 0, groupCount)
	totalContainers := float64(0)
	for i := 0; i < groupCount; i++ {
		totalContainers += float64(len(chunked[i]))
		messages = append(messages, &model.CollectorContainer{
			HostName:   cfg.HostName,
			Info:       c.sysInfo,
			Containers: chunked[i],
			GroupId:    groupID,
			GroupSize:  int32(groupCount),
		})
	}

	c.lastRates = util.ExtractContainerRateMetric(ctrList)
	c.lastRun = time.Now()

	s.Gauge("stackstate.process_agent.containers.host_count", totalContainers, cfg.HostName, []string{})
	log.Debugf("collected %d containers in %s", int(totalContainers), time.Now().Sub(start))
	return &CheckResult{
		CollectorMessages: messages,
		Metrics:           metrics,
	}, nil
}

// fmtContainers formats the ctrList
func fmtContainers(
	cfg *config.AgentConfig,
	ctrList []*containers.Container,
	lastRates map[string]util.ContainerRateMetrics,
	lastRun time.Time,
	multiMetricsEnabled bool,
) ([]*model.Container, []telemetry.RawMetrics) {

	containers := make([]*model.Container, 0, len(ctrList))
	multiMetrics := make([]telemetry.RawMetrics, 0)

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
		tags, err := tagger.Tag(ctr.EntityID, collectors.HighCardinality)
		if err != nil {
			log.Errorf("unable to retrieve tags for container: %s", err)
			tags = []string{}
		}

		container := &model.Container{
			Id:          ctr.ID,
			Type:        ctr.Type,
			CpuLimit:    float32(ctr.Limits.CPULimit),
			MemoryLimit: ctr.Limits.MemLimit,
			Created:     ctr.Created,
			State:       model.ContainerState(model.ContainerState_value[ctr.State]),
			Health:      model.ContainerHealth(model.ContainerHealth_value[ctr.Health]),
			Started:     ctr.StartedAt,
			Tags:        transformKubernetesTags(tags, cfg.ClusterName),
		}

		metricTags := []string{fmt.Sprintf("containerId:%s", ctr.ID)}
		timestamp := time.Now().Unix()
		makeMetric := func(name string, value float64) telemetry.RawMetrics {
			return telemetry.RawMetrics{
				Name: name, Timestamp: timestamp, HostName: cfg.HostName, Value: value, Tags: metricTags,
			}
		}

		// new metrics are sent regardless of feature flag which is needed for migration
		// cpuThrottledTime & cpuNrThrottled are accumulative values
		// https://engineering.indeedblog.com/blog/2019/12/unthrottled-fixing-cpu-limits-in-the-cloud/
		// so that's why rate is calculated
		multiMetrics = append(multiMetrics,
			makeMetric("cpuThrottledTime", calculateRateF64(ctr.CPU.ThrottledTime, lastCtr.CPU.ThrottledTime, lastRun)),
			makeMetric("cpuNrThrottled", float64(calculateRate(ctr.CPU.NrThrottled, lastCtr.CPU.NrThrottled, lastRun))),
			makeMetric("cpuThreadCount", float64(ctr.CPU.ThreadCount)),
		)

		if multiMetricsEnabled {
			log.Debugf("Generating container metrics for intake API (upgrade-to-multi-metrics feature is enabled)")
			multiMetrics = append(multiMetrics,
				makeMetric("rbps", float64(calculateRate(ctr.IO.ReadBytes, lastCtr.IO.ReadBytes, lastRun))),
				makeMetric("wbps", float64(calculateRate(ctr.IO.WriteBytes, lastCtr.IO.WriteBytes, lastRun))),
				makeMetric("netRcvdPs", float64(calculateRate(ifStats.PacketsRcvd, lastCtr.NetworkSum.PacketsRcvd, lastRun))),
				makeMetric("netSentPs", float64(calculateRate(ifStats.PacketsSent, lastCtr.NetworkSum.PacketsSent, lastRun))),
				makeMetric("netRcvdBps", float64(calculateRate(ifStats.BytesRcvd, lastCtr.NetworkSum.BytesRcvd, lastRun))),
				makeMetric("netSentBps", float64(calculateRate(ifStats.BytesSent, lastCtr.NetworkSum.BytesSent, lastRun))),
				makeMetric("userPct", float64(calculateCtrPct(ctr.CPU.User, lastCtr.CPU.User, sys2, sys1, cpus, lastRun))),
				makeMetric("systemPct", float64(calculateCtrPct(ctr.CPU.System, lastCtr.CPU.System, sys2, sys1, cpus, lastRun))),
				makeMetric("totalPct", float64(calculateCtrPct(ctr.CPU.User+ctr.CPU.System, lastCtr.CPU.User+lastCtr.CPU.System, sys2, sys1, cpus, lastRun))),
				makeMetric("memRss", float64(ctr.Memory.RSS)),
				makeMetric("memCache", float64(ctr.Memory.Cache)),
			)
		} else {
			log.Warnf("Generating container metrics for collector API (upgrade-to-multi-metrics feature is disabled)")
			container.Rbps = calculateRate(ctr.IO.ReadBytes, lastCtr.IO.ReadBytes, lastRun)
			container.Wbps = calculateRate(ctr.IO.WriteBytes, lastCtr.IO.WriteBytes, lastRun)
			container.NetRcvdPs = calculateRate(ifStats.PacketsRcvd, lastCtr.NetworkSum.PacketsRcvd, lastRun)
			container.NetSentPs = calculateRate(ifStats.PacketsSent, lastCtr.NetworkSum.PacketsSent, lastRun)
			container.NetRcvdBps = calculateRate(ifStats.BytesRcvd, lastCtr.NetworkSum.BytesRcvd, lastRun)
			container.NetSentBps = calculateRate(ifStats.BytesSent, lastCtr.NetworkSum.BytesSent, lastRun)
			container.UserPct = calculateCtrPct(ctr.CPU.User, lastCtr.CPU.User, sys2, sys1, cpus, lastRun)
			container.SystemPct = calculateCtrPct(ctr.CPU.System, lastCtr.CPU.System, sys2, sys1, cpus, lastRun)
			container.TotalPct = calculateCtrPct(ctr.CPU.User+ctr.CPU.System, lastCtr.CPU.User+lastCtr.CPU.System, sys2, sys1, cpus, lastRun)
			container.MemRss = ctr.Memory.RSS
			container.MemCache = ctr.Memory.Cache
		}

		containers = append(containers, container)
	}

	return containers, multiMetrics
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
		ctr.Memory = &metrics.ContainerMemStats{}
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
