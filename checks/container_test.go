package checks

import (
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics"
	"github.com/stretchr/testify/assert"
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
		cur, last []*containers.Container
		chunks    int
		expected  int
	}{
		{
			cur:      []*containers.Container{ctrs[0], ctrs[1], ctrs[2]},
			last:     []*containers.Container{ctrs[0], ctrs[1], ctrs[2]},
			chunks:   2,
			expected: 3,
		},
		{
			cur:      []*containers.Container{ctrs[0], ctrs[1], ctrs[2]},
			last:     []*containers.Container{ctrs[0], ctrs[2]},
			chunks:   2,
			expected: 3,
		},
		{
			cur:      []*containers.Container{ctrs[0], ctrs[2]},
			last:     []*containers.Container{ctrs[0], ctrs[1], ctrs[2]},
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
	cur := []*containers.Container{&containers.Container{}}
	last := []*containers.Container{&containers.Container{}}
	fmtContainers(cur, last, time.Now(), 10)
	fmtContainerStats(cur, last, time.Now(), 10)

	// Make sure we get values when we have nils in last.
	cur = []*containers.Container{
		&containers.Container{
			ID:  "1",
			CPU: &metrics.CgroupTimesStat{},
		},
	}
	last = []*containers.Container{
		&containers.Container{
			ID:     "1",
			Memory: &metrics.CgroupMemStat{},
		},
	}
	fmtContainers(cur, last, time.Now(), 10)
	fmtContainerStats(cur, last, time.Now(), 10)

}
