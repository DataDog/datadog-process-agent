package checks

import (
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/docker"
	"github.com/DataDog/gopsutil/cpu"
	"github.com/stretchr/testify/assert"
)

func makeContainer(id string) *docker.Container {
	return &docker.Container{
		ID:     id,
		CPU:    &docker.CgroupTimesStat{},
		Memory: &docker.CgroupMemStat{},
		IO:     &docker.CgroupIOStat{},
	}
}

func TestContainerChunking(t *testing.T) {
	ctrs := []*docker.Container{
		makeContainer("foo"),
		makeContainer("bar"),
		makeContainer("bim"),
	}
	lastRun := time.Now().Add(-5 * time.Second)
	syst1, syst2 := cpu.TimesStat{}, cpu.TimesStat{}

	for i, tc := range []struct {
		cur, last []*docker.Container
		chunks    int
		expected  int
	}{
		{
			cur:      []*docker.Container{ctrs[0], ctrs[1], ctrs[2]},
			last:     []*docker.Container{ctrs[0], ctrs[1], ctrs[2]},
			chunks:   2,
			expected: 3,
		},
		{
			cur:      []*docker.Container{ctrs[0], ctrs[1], ctrs[2]},
			last:     []*docker.Container{ctrs[0], ctrs[2]},
			chunks:   2,
			expected: 3,
		},
		{
			cur:      []*docker.Container{ctrs[0], ctrs[2]},
			last:     []*docker.Container{ctrs[0], ctrs[1], ctrs[2]},
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
