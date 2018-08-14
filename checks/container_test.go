package checks

import (
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics"
	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-process-agent/util"
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
