//go:build linux
// +build linux

package checks

import (
	"github.com/StackVista/stackstate-agent/pkg/telemetry"
	"testing"
	"time"

	"github.com/StackVista/stackstate-process-agent/config"

	"github.com/StackVista/stackstate-agent/pkg/util/containers"
	"github.com/StackVista/stackstate-agent/pkg/util/containers/metrics"
	"github.com/stretchr/testify/assert"

	"github.com/StackVista/stackstate-agent/pkg/process/util"
)

func makeContainer(id string) *containers.Container {
	ctn := &containers.Container{
		ID: id,
		ContainerMetrics: metrics.ContainerMetrics{
			CPU:    &metrics.ContainerCPUStats{},
			Memory: &metrics.ContainerMemStats{},
			IO:     &metrics.ContainerIOStats{},
		},
		Limits:  metrics.ContainerLimits{},
		Network: metrics.ContainerNetStats{},
	}

	return ctn
}

func TestTransformKubernetesTags(t *testing.T) {
	for _, tc := range []struct {
		name         string
		tags         []string
		expectedTags []string
		config       *config.AgentConfig
	}{
		{
			name:         "Should transform kubernetes tags from container and add the cluster name as a tag",
			tags:         []string{"pod_name:test-pod-name", "kube_namespace:test-kube-namespace"},
			expectedTags: []string{"pod-name:test-pod-name", "namespace:test-kube-namespace", "cluster-name:test-cluster-name"},
			config: func() *config.AgentConfig {
				cfg := config.NewDefaultAgentConfig()
				cfg.ClusterName = "test-cluster-name"
				return cfg
			}(),
		},
		{
			name:         "Should not transform any tags that are not part of the kubernetes set",
			tags:         []string{"some-other:tag", "pod_name:test-pod-name", "kube_namespace:test-kube-namespace"},
			expectedTags: []string{"some-other:tag", "pod-name:test-pod-name", "namespace:test-kube-namespace"},
			config:       config.NewDefaultAgentConfig(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tags := transformKubernetesTags(tc.tags, tc.config.ClusterName)

			assert.EqualValues(t, tc.expectedTags, tags)
		})
	}

}

func TestContainerNewMetricsFeatureFlag(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	ctrs := []*containers.Container{
		makeContainer("foo"),
	}
	prevCtrs := []*containers.Container{
		makeContainer("foo"),
	}
	lastRun := time.Now().Add(-5 * time.Second)

	findMetric := func(metrics []telemetry.RawMetrics, name string) *telemetry.RawMetrics {
		for _, metric := range metrics {
			if metric.Name == name {
				return &metric
			}
		}
		return nil
	}

	prevCtrs[0].CPU.ThrottledTime = 500
	ctrs[0].CPU.ThrottledTime = 1000

	prevCtrs[0].CPU.NrThrottled = 0
	ctrs[0].CPU.NrThrottled = 100

	prevCtrs[0].CPU.System = 0
	ctrs[0].CPU.System = 20

	cnts, metrics := fmtContainers(cfg, ctrs, util.ExtractContainerRateMetric(prevCtrs), lastRun, false)
	assert.Equal(t, cnts[0].SystemPct, float64(20/5))
	assert.Len(t, metrics, 3, "Only new metrics are expected to appear when feature-flag is disabled")
	assert.Equal(t, findMetric(metrics, "cpuThrottledTime").Value, float64(1000-500)/5)
	assert.Equal(t, findMetric(metrics, "cpuNrThrottled").Value, float64(100)/5)
	assert.Equal(t, findMetric(metrics, "cpuThreadCount").Value, float64(0))

	cnts2, metrics2 := fmtContainers(cfg, ctrs, util.ExtractContainerRateMetric(prevCtrs), lastRun, true)
	assert.Equal(t, cnts2[0].SystemPct, 0, "When multimetrics enabled, collector's structures metrics should be 0")
	assert.Len(t, metrics2, 11+3)
	assert.Equal(t, findMetric(metrics2, "cpuThrottledTime").Value, float64(1000-500)/5)
	assert.Equal(t, findMetric(metrics2, "cpuNrThrottled").Value, float64(100)/5)
	assert.Equal(t, findMetric(metrics, "cpuThreadCount").Value, 0)
	assert.Equal(t, findMetric(metrics, "systemPct").Value, float64(20)/5)

}

func TestContainerChunking(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	ctrs := []*containers.Container{
		makeContainer("foo"),
		makeContainer("bar"),
		makeContainer("bim"),
	}
	lastRun := time.Now().Add(-5 * time.Second)

	for i, tc := range []struct {
		cur      []*containers.Container
		last     map[string]util.ContainerRateMetrics
		chunks   int
		expected int
	}{
		{
			cur:      []*containers.Container{ctrs[0], ctrs[1], ctrs[2]},
			last:     util.ExtractContainerRateMetric([]*containers.Container{ctrs[0], ctrs[1], ctrs[2]}),
			chunks:   2,
			expected: 3,
		},
		{
			cur:      []*containers.Container{ctrs[0], ctrs[1], ctrs[2]},
			last:     util.ExtractContainerRateMetric([]*containers.Container{ctrs[0], ctrs[2]}),
			chunks:   2,
			expected: 3,
		},
		{
			cur:      []*containers.Container{ctrs[0], ctrs[2]},
			last:     util.ExtractContainerRateMetric([]*containers.Container{ctrs[0], ctrs[1], ctrs[2]}),
			chunks:   20,
			expected: 2,
		},
	} {
		containers, _ := fmtContainers(cfg, tc.cur, tc.last, lastRun, true)
		chunked := chunkedContainers(containers, tc.chunks)
		assert.Len(t, chunked, tc.chunks, "len test %d", i)
		total := 0
		for _, c := range chunked {
			total += len(c)
		}
		assert.Equal(t, tc.expected, total, "total test %d", i)

		chunkedStat := fmtContainerStats(tc.cur, tc.last, lastRun, tc.chunks)
		assert.Len(t, chunkedStat, tc.chunks, "len stat test %d", i)
		total = 0
		for _, c := range chunked {
			total += len(c)
		}
		assert.Equal(t, tc.expected, total, "total test %d", i)

	}
}

func TestContainerNils(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	// Make sure formatting doesn't crash with nils
	cur := []*containers.Container{{}}
	last := map[string]util.ContainerRateMetrics{}
	fmtContainers(cfg, cur, last, time.Now(), true)
	fmtContainerStats(cur, last, time.Now(), 10)
	// Make sure we get values when we have nils in last.
	cur = []*containers.Container{
		{
			ID: "1",
			ContainerMetrics: metrics.ContainerMetrics{
				CPU: &metrics.ContainerCPUStats{},
			},
		},
	}
	last = map[string]util.ContainerRateMetrics{
		"1": {
			CPU: &metrics.ContainerCPUStats{},
		},
	}
	fmtContainers(cfg, cur, last, time.Now(), true)
	fmtContainerStats(cur, last, time.Now(), 10)
}
