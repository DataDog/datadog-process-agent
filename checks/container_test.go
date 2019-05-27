// +build linux

package checks

import (
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

func TestContainerChunking(t *testing.T) {
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
		chunked := fmtContainers(tc.cur, tc.last, lastRun, tc.chunks)
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
	// Make sure formatting doesn't crash with nils
	cur := []*containers.Container{{}}
	last := map[string]util.ContainerRateMetrics{}
	fmtContainers(cur, last, time.Now(), 10)
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
	fmtContainers(cur, last, time.Now(), 10)
	fmtContainerStats(cur, last, time.Now(), 10)
}
