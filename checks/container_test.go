// +build linux

package checks

import (
	"github.com/StackVista/stackstate-process-agent/config"
	"testing"
	"time"

	"github.com/StackVista/stackstate-agent/pkg/util/containers"
	"github.com/StackVista/stackstate-agent/pkg/util/containers/metrics"
	"github.com/stretchr/testify/assert"

	"github.com/StackVista/stackstate-process-agent/util"
)

func makeContainer(id string) *containers.Container {
	return &containers.Container{
		ID:     id,
		CPU:    &metrics.CgroupTimesStat{},
		Memory: &metrics.CgroupMemStat{},
		IO:     &metrics.CgroupIOStat{},
	}
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
		chunked := chunkedContainers(fmtContainers(cfg, tc.cur, tc.last, lastRun), tc.chunks)
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
	fmtContainers(cfg, cur, last, time.Now())
	fmtContainerStats(cur, last, time.Now(), 10)
	// Make sure we get values when we have nils in last.
	cur = []*containers.Container{
		{
			ID:  "1",
			CPU: &metrics.CgroupTimesStat{},
		},
	}
	last = map[string]util.ContainerRateMetrics{
		"1": {
			CPU: &metrics.CgroupTimesStat{},
		},
	}
	fmtContainers(cfg, cur, last, time.Now())
	fmtContainerStats(cur, last, time.Now(), 10)
}
