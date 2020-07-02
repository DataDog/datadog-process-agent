package checks

import (
	"fmt"
	"github.com/DataDog/gopsutil/cpu"
	"github.com/StackVista/stackstate-agent/pkg/util/containers"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
	"github.com/patrickmn/go-cache"
	"regexp"
	"sort"

	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/gopsutil/process"
	"github.com/stretchr/testify/assert"
)

func makeProcessWithResource(pid int32, cmdline string, resMemory, readCount, writeCount uint64, userCPU, systemCPU float64) *process.FilledProcess {
	return &process.FilledProcess{
		Pid:         pid,
		CreateTime:  time.Now().Add(-5 * time.Minute).Unix(),
		Cmdline:     strings.Split(cmdline, " "),
		MemInfo:     &process.MemoryInfoStat{RSS: resMemory},
		CtxSwitches: &process.NumCtxSwitchesStat{},
		IOStat:      &process.IOCountersStat{ReadCount: readCount, WriteCount: writeCount},
		CpuTime: cpu.TimesStat{
			User: userCPU, System: systemCPU, Nice: 0, Iowait: 0, Irq: 0, Softirq: 0, Steal: 0, Guest: 0,
			GuestNice: 0, Idle: 0, Stolen: 0,
		},
	}
}

func makeProcess(pid int32) *model.Process {
	return &model.Process{
		Pid: pid,
	}
}

func makeProcessWithContainer(pid int32, containerID string) *model.Process {
	return &model.Process{
		Pid:         pid,
		ContainerId: containerID,
	}
}

func makeTaggedProcess(pid int32, tags []string) *model.Process {
	return &model.Process{
		Pid:  pid,
		Tags: tags,
	}
}

func makeTaggedProcessWithContainer(pid int32, containerID string, tags []string) *model.Process {
	return &model.Process{
		Pid:         pid,
		ContainerId: containerID,
		Tags:        tags,
	}
}

func makeModelContainer(id string) *model.Container {
	return &model.Container{
		Id: id,
	}
}

func makeTaggedModelContainer(id string, tags []string) *model.Container {
	return &model.Container{
		Id:   id,
		Tags: tags,
	}
}

func makeProcessStat(pid int32) *model.ProcessStat {
	return &model.ProcessStat{
		Pid: pid,
	}
}

func TestProcessChunking(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()

	processes := []*model.Process{
		makeProcess(1),
		makeProcess(2),
		makeProcess(3),
		makeProcess(4),
		makeProcess(5),
		makeProcess(6),
		makeProcess(7),
		makeProcess(8),
		makeProcess(9),
		makeProcess(10),
		makeProcess(11),
		makeProcess(12),
		makeProcess(13),
		makeProcess(14),
		makeProcess(15),
		makeProcess(16),
		makeProcess(17),
		makeProcess(18),
		makeProcess(19),
		makeProcess(20),
		makeProcess(21),
	}
	processStats := []*model.ProcessStat{
		makeProcessStat(1),
		makeProcessStat(2),
		makeProcessStat(3),
		makeProcessStat(4),
		makeProcessStat(5),
		makeProcessStat(6),
		makeProcessStat(7),
		makeProcessStat(8),
		makeProcessStat(9),
		makeProcessStat(10),
		makeProcessStat(11),
		makeProcessStat(12),
		makeProcessStat(13),
		makeProcessStat(14),
		makeProcessStat(15),
		makeProcessStat(16),
		makeProcessStat(17),
		makeProcessStat(18),
		makeProcessStat(19),
		makeProcessStat(20),
		makeProcessStat(21),
	}

	for _, tc := range []struct {
		name           string
		maxSize        int
		expectedTotal  int
		expectedChunks int
	}{
		{
			name:           "Should create 7 chunks of 3 items and have a total of 21 items",
			maxSize:        3,
			expectedTotal:  21,
			expectedChunks: 7,
		},
		{
			name:           "Should create 1 chunk with 21 items and have a total of 21 items",
			maxSize:        21,
			expectedTotal:  21,
			expectedChunks: 1,
		},
	} {
		cfg.MaxPerMessage = tc.maxSize

		t.Run(tc.name, func(t *testing.T) {
			chunked := chunkProcesses(processes, tc.maxSize, make([][]*model.Process, 0, cfg.MaxPerMessage))
			assert.Len(t, chunked, tc.expectedChunks, "Test: [%s], expected chunks: %d, found chunks: %d", tc.name, tc.expectedChunks, len(chunked))
			total := 0
			for _, c := range chunked {
				total += len(c)
			}
			assert.Equal(t, total, tc.expectedTotal, "Test: [%s], expected total: %d, found total: %d", tc.name, tc.expectedTotal, total)

			chunkedStat := chunkProcessStats(processStats, tc.maxSize, make([][]*model.ProcessStat, 0, cfg.MaxPerMessage))
			assert.Len(t, chunkedStat, tc.expectedChunks, "Test: [%s], expected stats chunks: %d, found stats chunks: %d", tc.name, tc.expectedChunks, len(chunkedStat))
			total = 0
			for _, c := range chunkedStat {
				total += len(c)
			}
			assert.Equal(t, total, tc.expectedTotal, "Test: [%s], expected stats total: %d, found stats total: %d", tc.name, tc.expectedTotal, total)
		})
	}
}

func TestProcessBlacklisting(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()

	for _, tc := range []struct {
		name      string
		blacklist []string
		process   *ProcessCommon
		expected  bool
	}{
		{
			name:      "Should filter process based on Blacklist",
			blacklist: []string{"process-name"},
			process: &ProcessCommon{
				Pid: 1,
				Command: &model.Command{
					Args:   []string{"process-name", "arguments"},
					Cwd:    "this/working/directory",
					Root:   "",
					OnDisk: false,
					Exe:    "path/to/executable",
				},
			},
			expected: false,
		},
		{
			name:      "Should filter process with empty arguments",
			blacklist: []string{},
			process: &ProcessCommon{
				Pid: 1,
				Command: &model.Command{
					Args:   []string{},
					Cwd:    "this/working/directory",
					Root:   "",
					OnDisk: false,
					Exe:    "path/to/executable",
				},
			},
			expected: false,
		},
		{
			name:      "Should filter unknown process without arguments or exe",
			blacklist: []string{},
			process: &ProcessCommon{
				Pid: 1,
				Command: &model.Command{
					Args:   []string{},
					Cwd:    "this/working/directory",
					Root:   "",
					OnDisk: false,
					Exe:    "",
				},
			},
			expected: false,
		},
		{
			name:      "Should not filter process with arguments that does not match a pattern in the blacklist",
			blacklist: []string{"non-matching-pattern"},
			process: &ProcessCommon{
				Pid: 1,
				Command: &model.Command{
					Args:   []string{"some", "args"},
					Cwd:    "this/working/directory",
					Root:   "",
					OnDisk: false,
					Exe:    "",
				},
			},
			expected: true,
		},
		{
			name: "Should filter process with arguments that does not match a pattern in the blacklist, but is not " +
				"observed for longer than the configured short-lived seconds",
			blacklist: []string{"non-matching-pattern"},
			process: &ProcessCommon{
				Pid:           1,
				Identifier:    fmt.Sprintf("1:%d", time.Now().Add(-5*time.Millisecond).Unix()),
				FirstObserved: time.Now().Add(-5 * time.Millisecond).Unix(),
				Command: &model.Command{
					Args:   []string{"some", "args"},
					Cwd:    "this/working/directory",
					Root:   "",
					OnDisk: false,
					Exe:    "",
				},
			},
			expected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bl := make([]*regexp.Regexp, 0, len(tc.blacklist))
			for _, s := range tc.blacklist {
				bl = append(bl, regexp.MustCompile(s))
			}
			cfg.Blacklist = bl

			filter := keepProcess(cfg)(tc.process)
			assert.Equal(t, tc.expected, filter, "Test: [%s], expected filter: %t, found filter: %t", tc.name, tc.expected, filter)
		})
	}
}

func TestProcessInclusions(t *testing.T) {
	type Tags = map[string]struct{}
	for _, tc := range []struct {
		name                        string
		processes                   []*ProcessCommon
		amountTopCPUPercentageUsage int
		cpuPercentageUsageThreshold int
		amountTopIOReadUsage        int
		amountTopIOWriteUsage       int
		amountTopMemoryUsage        int
		memoryUsageThreshold        int
		expectedPidsTags            []struct {
			Pid  int
			Tags Tags
		}
		totalCPUpercentage float32
		totalMemory        uint64
	}{
		{
			name: "Should return the correct top resource using processes",
			processes: []*ProcessCommon{
				{
					Pid:    1,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 20},
				},
				{
					Pid:    2,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 80},
				},
				{
					Pid:    3,
					CPU:    &model.CPUStat{TotalPct: 50},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    4,
					CPU:    &model.CPUStat{TotalPct: 80},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    5,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 10, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    6,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 50, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    7,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 50},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    8,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 80},
					Memory: &model.MemoryStat{Rss: 0},
				},
			},
			amountTopCPUPercentageUsage: 1,
			cpuPercentageUsageThreshold: 20,
			amountTopIOReadUsage:        1,
			amountTopIOWriteUsage:       1,
			amountTopMemoryUsage:        1,
			memoryUsageThreshold:        35,
			expectedPidsTags: []struct {
				Pid  int
				Tags Tags
			}{
				{2, map[string]struct{}{TopMemory: {}}},
				{4, map[string]struct{}{TopCPU: {}}},
				{6, map[string]struct{}{TopIORead: {}}},
				{8, map[string]struct{}{TopIOWrite: {}}},
			},
			totalCPUpercentage: 25,
			totalMemory:        40,
		},
		{
			name: "Should independently return the process which consumed the most resources for each of the categories",
			processes: []*ProcessCommon{
				{
					Pid:    1,
					CPU:    &model.CPUStat{TotalPct: 100},
					IOStat: &model.IOStat{ReadRate: 100, WriteRate: 100},
					Memory: &model.MemoryStat{Rss: 100},
				},
				{
					Pid:    2,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 80},
				},
				{
					Pid:    3,
					CPU:    &model.CPUStat{TotalPct: 50},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    4,
					CPU:    &model.CPUStat{TotalPct: 80},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    5,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 10, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    6,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 50, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    7,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 50},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    8,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 80},
					Memory: &model.MemoryStat{Rss: 0},
				},
			},
			amountTopCPUPercentageUsage: 1,
			cpuPercentageUsageThreshold: 20,
			amountTopIOReadUsage:        1,
			amountTopIOWriteUsage:       1,
			amountTopMemoryUsage:        1,
			memoryUsageThreshold:        35,
			expectedPidsTags: []struct {
				Pid  int
				Tags Tags
			}{{1, map[string]struct{}{TopMemory: {}, TopCPU: {}, TopIORead: {}, TopIOWrite: {}}}},
			totalCPUpercentage: 25,
			totalMemory:        40,
		},
		{
			name: "Should not return CPU / Memory top consuming processes when the thresholds are not exceeded",
			processes: []*ProcessCommon{
				{
					Pid:    1,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 20},
				},
				{
					Pid:    2,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 80},
				},
				{
					Pid:    3,
					CPU:    &model.CPUStat{TotalPct: 50},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    4,
					CPU:    &model.CPUStat{TotalPct: 80},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    5,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 10, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    6,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 50, WriteRate: 0},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    7,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 50},
					Memory: &model.MemoryStat{Rss: 0},
				},
				{
					Pid:    8,
					CPU:    &model.CPUStat{TotalPct: 0},
					IOStat: &model.IOStat{ReadRate: 0, WriteRate: 80},
					Memory: &model.MemoryStat{Rss: 0},
				},
			},
			amountTopCPUPercentageUsage: 1,
			cpuPercentageUsageThreshold: 20,
			amountTopIOReadUsage:        1,
			amountTopIOWriteUsage:       1,
			amountTopMemoryUsage:        1,
			memoryUsageThreshold:        35,
			expectedPidsTags: []struct {
				Pid  int
				Tags Tags
			}{
				{6, map[string]struct{}{TopIORead: {}}},
				{8, map[string]struct{}{TopIOWrite: {}}},
			},
			totalCPUpercentage: 10,
			totalMemory:        10,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.NewDefaultAgentConfig()
			cfg.AmountTopCPUPercentageUsage = tc.amountTopCPUPercentageUsage
			cfg.CPUPercentageUsageThreshold = tc.cpuPercentageUsageThreshold
			cfg.AmountTopIOReadUsage = tc.amountTopIOReadUsage
			cfg.AmountTopIOWriteUsage = tc.amountTopIOWriteUsage
			cfg.AmountTopMemoryUsage = tc.amountTopMemoryUsage
			cfg.MemoryUsageThreshold = tc.memoryUsageThreshold
			maxTopProcesses := cfg.AmountTopCPUPercentageUsage + cfg.AmountTopIOReadUsage + cfg.AmountTopIOWriteUsage + cfg.AmountTopMemoryUsage

			processInclusions := getProcessInclusions(tc.processes, cfg, tc.totalCPUpercentage, tc.totalMemory)
			assert.True(t, len(processInclusions) <= maxTopProcesses, fmt.Sprintf("Way too many top processes reported: %d > %d", len(processInclusions), maxTopProcesses))

			for _, proc := range processInclusions {
				sort.Strings(proc.Tags)
				pidTags := struct {
					Pid  int
					Tags Tags
				}{int(proc.Pid), deriveSet(proc.Tags)}
				assert.Contains(t, tc.expectedPidsTags, pidTags, fmt.Sprintf("Expected pids/tags: %v, found pid/tag: %v", tc.expectedPidsTags, pidTags))
			}
		})
	}
}

func TestBuildIncrementProcesses(t *testing.T) {
	pLast := []*model.Process{
		makeProcess(1),
		makeTaggedProcess(2, []string{"tag"}),
		makeTaggedProcess(3, []string{"oldtag"}),
	}
	pNow := []*model.Process{
		makeTaggedProcess(2, []string{"tag"}),
		makeTaggedProcess(3, []string{"newtag"}),
		makeProcess(4),
	}

	commands := buildIncrement(pNow, []*model.Container{}, buildProcState(pLast), make(map[string]*model.Container))

	expected := []*model.CollectorCommand{
		{
			Command: &model.CollectorCommand_UpdateProcessMetrics{
				UpdateProcessMetrics: makeTaggedProcess(2, []string{"tag"}),
			},
		},
		{
			Command: &model.CollectorCommand_UpdateProcess{
				UpdateProcess: makeTaggedProcess(3, []string{"newtag"}),
			},
		},
		{
			Command: &model.CollectorCommand_UpdateProcess{
				UpdateProcess: makeProcess(4),
			},
		},
		{
			Command: &model.CollectorCommand_DeleteProcess{
				DeleteProcess: makeProcess(1),
			},
		},
	}

	assert.Equal(t, len(expected), len(commands))

	for i := 0; i < len(expected); i++ {
		assert.EqualValues(t, expected[i], commands[i])
	}
}

func TestBuildIncrementContainers(t *testing.T) {
	cLast := []*model.Container{
		makeModelContainer("1"),
		makeTaggedModelContainer("2", []string{"tag"}),
		makeTaggedModelContainer("3", []string{"oldtag"}),
	}
	cNow := []*model.Container{
		makeTaggedModelContainer("2", []string{"tag"}),
		makeTaggedModelContainer("3", []string{"newtag"}),
		makeModelContainer("4"),
	}

	commands := buildIncrement([]*model.Process{}, cNow, make(map[int32]*model.Process), buildCtrState(cLast))

	expected := []*model.CollectorCommand{
		{
			Command: &model.CollectorCommand_UpdateContainerMetrics{
				UpdateContainerMetrics: makeTaggedModelContainer("2", []string{"tag"}),
			},
		},
		{
			Command: &model.CollectorCommand_UpdateContainer{
				UpdateContainer: makeTaggedModelContainer("3", []string{"newtag"}),
			},
		},
		{
			Command: &model.CollectorCommand_UpdateContainer{
				UpdateContainer: makeModelContainer("4"),
			},
		},
		{
			Command: &model.CollectorCommand_DeleteContainer{
				DeleteContainer: makeModelContainer("1"),
			},
		},
	}

	assert.Equal(t, len(expected), len(commands))

	for i := 0; i < len(expected); i++ {
		assert.EqualValues(t, expected[i], commands[i])
	}
}

func TestBuildIncrementContainersProcessKubernetesReplication(t *testing.T) {

	for _, tc := range []struct {
		name             string
		processes        []*model.Process
		lastProcesses    map[int32]*model.Process
		containers       []*model.Container
		lastContainers   map[string]*model.Container
		expectedCommands []*model.CollectorCommand
	}{
		{
			name: "Should replicate only kubernetes tags from container onto the process",
			processes: []*model.Process{
				makeProcessWithContainer(1, "123"),
			},
			lastProcesses: map[int32]*model.Process{},
			containers: []*model.Container{
				makeTaggedModelContainer("123", []string{"non-replicate:tag", "cluster-name:test-cluster-name", "pod-name:some-pod-name-xyz", "namespace:some-namespace"}),
			},
			lastContainers: map[string]*model.Container{},
			expectedCommands: []*model.CollectorCommand{
				{
					Command: &model.CollectorCommand_UpdateContainer{
						UpdateContainer: makeTaggedModelContainer("123", []string{"non-replicate:tag", "cluster-name:test-cluster-name", "pod-name:some-pod-name-xyz", "namespace:some-namespace"}),
					},
				},
				{
					Command: &model.CollectorCommand_UpdateProcess{
						UpdateProcess: makeTaggedProcessWithContainer(1, "123", []string{"cluster-name:test-cluster-name", "pod-name:some-pod-name-xyz", "namespace:some-namespace"}),
					},
				},
			},
		},
		{
			name: "Should update a process with kubernetes tags from a container",
			processes: []*model.Process{
				makeProcessWithContainer(1, "123"),
			},
			lastProcesses: map[int32]*model.Process{},
			containers: []*model.Container{
				makeTaggedModelContainer("123", []string{"cluster-name:test-cluster-name", "pod-name:some-pod-name-xyz", "namespace:some-namespace"}),
			},
			lastContainers: map[string]*model.Container{
				"123": makeTaggedModelContainer("123", []string{"cluster-name:test-cluster-name", "pod-name:some-pod-name-xyz", "namespace:some-namespace"}),
			},
			expectedCommands: []*model.CollectorCommand{
				{
					Command: &model.CollectorCommand_UpdateContainerMetrics{
						UpdateContainerMetrics: makeTaggedModelContainer("123", []string{"cluster-name:test-cluster-name", "pod-name:some-pod-name-xyz", "namespace:some-namespace"}),
					},
				},
				{
					Command: &model.CollectorCommand_UpdateProcess{
						UpdateProcess: makeTaggedProcessWithContainer(1, "123", []string{"cluster-name:test-cluster-name", "pod-name:some-pod-name-xyz", "namespace:some-namespace"}),
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commands := buildIncrement(tc.processes, tc.containers, tc.lastProcesses, tc.lastContainers)
			assert.EqualValues(t, tc.expectedCommands, commands)
		})
	}
}

func TestEnrichProcessWithKubernetesTags(t *testing.T) {

	for _, tc := range []struct {
		name              string
		processes         []*model.Process
		containers        []*model.Container
		expectedProcesses []*model.Process
	}{
		{
			name: "Should replicate tags from Kubernetes container onto the process",
			processes: []*model.Process{
				makeProcessWithContainer(1, "123"),
			},
			containers: []*model.Container{
				makeTaggedModelContainer("123", []string{"cluster-name:test-cluster-name", "pod-name:some-pod-name-xyz", "namespace:some-namespace"}),
			},
			expectedProcesses: []*model.Process{
				makeTaggedProcessWithContainer(1, "123", []string{"cluster-name:test-cluster-name", "pod-name:some-pod-name-xyz", "namespace:some-namespace"}),
			},
		},
		{
			name: "Should do nothing with processes not running in a container",
			processes: []*model.Process{
				makeProcess(1),
			},
			containers: []*model.Container{},
			expectedProcesses: []*model.Process{
				makeProcess(1),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			processes := enrichProcessWithKubernetesTags(tc.processes, tc.containers)
			assert.EqualValues(t, tc.expectedProcesses, processes)
		})
	}
}

func TestBuildIncrementContainerPrecedeProcesses(t *testing.T) {
	cNow := []*model.Container{
		makeModelContainer("1"),
	}

	pNow := []*model.Process{
		makeProcess(1),
	}

	commands := buildIncrement(pNow, cNow, make(map[int32]*model.Process), make(map[string]*model.Container))

	expected := []*model.CollectorCommand{
		{
			Command: &model.CollectorCommand_UpdateContainer{
				UpdateContainer: makeModelContainer("1"),
			},
		},
		{
			Command: &model.CollectorCommand_UpdateProcess{
				UpdateProcess: makeProcess(1),
			},
		},
	}

	assert.Equal(t, len(expected), len(commands))

	for i := 0; i < len(expected); i++ {
		assert.EqualValues(t, expected[i], commands[i])
	}
}

func TestProcessFormatting(t *testing.T) {
	now := time.Now()

	pNow := []*process.FilledProcess{
		// generic processes
		makeProcessWithResource(1, "git clone google.com", 0, 0, 0, 0, 0),
		makeProcessWithResource(2, "mine-bitcoins -all -x", 0, 0, 0, 0, 0),
		makeProcessWithResource(3, "datadog-process-agent -ddconfig datadog.conf", 0, 0, 0, 0, 0),
		makeProcessWithResource(4, "foo -bar -bim", 0, 0, 0, 0, 0),
		// resource intensive processes
		// cpu resource intensive processes
		makeProcessWithResource(5, "cpu resource process 1", 0, 0, 0, 20, 20),
		makeProcessWithResource(6, "cpu resource process 2", 0, 0, 0, 35, 60),
		makeProcessWithResource(7, "cpu resource process 3", 0, 0, 0, 11, 15),
		makeProcessWithResource(8, "cpu resource process 4", 0, 0, 0, 26, 12),
		makeProcessWithResource(9, "cpu resource process 5", 0, 0, 0, 21, 16),
		// memory resource intensive processes
		makeProcessWithResource(10, "memory resource process 1", 50, 0, 0, 0, 0),
		makeProcessWithResource(11, "memory resource process 2", 150, 0, 0, 0, 0),
		makeProcessWithResource(12, "memory resource process 3", 100, 0, 0, 0, 0),
		makeProcessWithResource(13, "memory resource process 4", 200, 0, 0, 0, 0),
		// read io resource intensive processes
		makeProcessWithResource(14, "read io resource process 1", 0, 80, 0, 0, 0),
		makeProcessWithResource(15, "read io resource process 2", 0, 40, 0, 0, 0),
		makeProcessWithResource(16, "read io resource process 3", 0, 120, 0, 0, 0),
		makeProcessWithResource(17, "read io resource process 4", 0, 90, 0, 0, 0),
		// write io resource intensive processes
		makeProcessWithResource(18, "write io resource process 1", 0, 0, 20, 0, 0),
		makeProcessWithResource(19, "write io resource process 2", 0, 0, 60, 0, 0),
		makeProcessWithResource(20, "write io resource process 3", 0, 0, 80, 0, 0),
		makeProcessWithResource(21, "write io resource process 4", 0, 0, 70, 0, 0),
	}
	pLast := []*process.FilledProcess{
		// generic processes
		makeProcessWithResource(1, "git clone google.com", 0, 0, 0, 0, 0),
		makeProcessWithResource(2, "mine-bitcoins -all -x", 0, 0, 0, 0, 0),
		makeProcessWithResource(3, "datadog-process-agent -ddconfig datadog.conf", 0, 0, 0, 0, 0),
		makeProcessWithResource(4, "foo -bar -bim", 0, 0, 0, 0, 0),
		// resource intensive processes
		// cpu resource intensive processes
		makeProcessWithResource(5, "cpu resource process 1", 0, 0, 0, 4, 10),
		makeProcessWithResource(6, "cpu resource process 2", 0, 0, 0, 4, 10),
		makeProcessWithResource(7, "cpu resource process 3", 0, 0, 0, 4, 10),
		makeProcessWithResource(8, "cpu resource process 4", 0, 0, 0, 4, 10),
		makeProcessWithResource(9, "cpu resource process 5", 0, 0, 0, 4, 10),
		// memory resource intensive processes
		makeProcessWithResource(10, "memory resource process 1", 50, 0, 0, 0, 0),
		makeProcessWithResource(11, "memory resource process 2", 150, 0, 0, 0, 0),
		makeProcessWithResource(12, "memory resource process 3", 100, 0, 0, 0, 0),
		makeProcessWithResource(13, "memory resource process 4", 200, 0, 0, 0, 0),
		// read io resource intensive processes
		makeProcessWithResource(14, "read io resource process 1", 0, 10, 0, 0, 0),
		makeProcessWithResource(15, "read io resource process 2", 0, 10, 0, 0, 0),
		makeProcessWithResource(16, "read io resource process 3", 0, 10, 0, 0, 0),
		makeProcessWithResource(17, "read io resource process 4", 0, 10, 0, 0, 0),
		// write io resource intensive processes
		makeProcessWithResource(18, "write io resource process 1", 0, 0, 10, 0, 0),
		makeProcessWithResource(19, "write io resource process 2", 0, 0, 10, 0, 0),
		makeProcessWithResource(20, "write io resource process 3", 0, 0, 10, 0, 0),
		makeProcessWithResource(21, "write io resource process 4", 0, 0, 10, 0, 0),
	}
	var containers []*containers.Container
	lastRun := time.Now().Add(-5 * time.Second)
	syst1, syst2 := cpu.TimesStat{
		User: 10, System: 20, Nice: 0, Iowait: 0, Irq: 0, Softirq: 0, Steal: 0, Guest: 0,
		GuestNice: 0, Idle: 0, Stolen: 0,
	}, cpu.TimesStat{
		User: 20, System: 40, Nice: 0, Iowait: 0, Irq: 0, Softirq: 0, Steal: 0, Guest: 0,
		GuestNice: 0, Idle: 0, Stolen: 0,
	}

	for i, tc := range []struct {
		name                        string
		cur, last                   []*process.FilledProcess
		maxSize                     int
		blacklist                   []string
		expectedTotal               int
		expectedChunks              int
		amountTopCPUPercentageUsage int
		amountTopIOReadUsage        int
		amountTopIOWriteUsage       int
		amountTopMemoryUsage        int
		expectedPids                []int32
	}{
		{
			name:                        "Expects all the processes to be present and chunked into 3 processes per chunk",
			cur:                         pNow,
			last:                        pLast,
			maxSize:                     3,
			blacklist:                   []string{},
			expectedTotal:               21,
			expectedChunks:              7,
			amountTopCPUPercentageUsage: 2,
			amountTopIOReadUsage:        2,
			amountTopIOWriteUsage:       2,
			amountTopMemoryUsage:        2,
			expectedPids:                []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21},
		},
		{
			name:                        "Expects all the processes not listed in the blacklist to be present as well as the top resource consuming processes regardless of whether they are blacklisted or not",
			cur:                         pNow,
			last:                        pLast,
			maxSize:                     3,
			blacklist:                   []string{"resource process"},
			expectedTotal:               12,
			expectedChunks:              4,
			amountTopCPUPercentageUsage: 2,
			amountTopIOReadUsage:        2,
			amountTopIOWriteUsage:       2,
			amountTopMemoryUsage:        2,
			expectedPids:                []int32{1, 2, 3, 4, 5, 6, 11, 13, 16, 17, 20, 21},
		},
		{
			name:                        "Expects all the top resource consuming process only to be present in a single chunk",
			cur:                         pNow,
			last:                        pLast,
			maxSize:                     7,
			blacklist:                   []string{"resource process", "git", "datadog", "foo", "mine"},
			expectedTotal:               7,
			expectedChunks:              1,
			amountTopCPUPercentageUsage: 2,
			amountTopIOReadUsage:        1,
			amountTopIOWriteUsage:       1,
			amountTopMemoryUsage:        3,
			expectedPids:                []int32{5, 6, 11, 12, 13, 16, 20},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.NewDefaultAgentConfig()

			bl := make([]*regexp.Regexp, 0, len(tc.blacklist))
			for _, s := range tc.blacklist {
				bl = append(bl, regexp.MustCompile(s))
			}
			cfg.Blacklist = bl
			cfg.MaxPerMessage = tc.maxSize

			cfg.AmountTopCPUPercentageUsage = tc.amountTopCPUPercentageUsage
			cfg.AmountTopMemoryUsage = tc.amountTopMemoryUsage
			cfg.AmountTopIOReadUsage = tc.amountTopIOReadUsage
			cfg.AmountTopIOWriteUsage = tc.amountTopIOWriteUsage

			cur := make(map[int32]*process.FilledProcess)
			for _, c := range tc.cur {
				c.CpuTime.Timestamp = 60 * 100 //in Windows uses CPUTime.Timestamp set to now in nanos
				cur[c.Pid] = c
			}
			last := make(map[int32]*process.FilledProcess)
			for _, c := range tc.last {
				c.CpuTime.Timestamp = 30 * 100 //in Windows uses CPUTime.Timestamp set to now in nanos
				last[c.Pid] = c
			}

			Process.Init(cfg, &model.SystemInfo{})

			// fill in the process cache
			for _, fp := range tc.last {
				fillProcessCache(Process.cache, fp, now.Add(-5*time.Minute).Unix(), now.Unix())
			}

			chunked := chunkProcesses(Process.fmtProcesses(cfg, cur, containers, syst2, syst1, lastRun), cfg.MaxPerMessage, make([][]*model.Process, 0))
			assert.Len(t, chunked, tc.expectedChunks, "len %d", i)
			total := 0
			pids := make([]int32, 0)
			for _, c := range chunked {
				total += len(c)
				for _, proc := range c {
					pids = append(pids, proc.Pid)
				}
			}
			assert.Equal(t, tc.expectedTotal, total, "total test %d", i)
			sort.Slice(pids, func(i, j int) bool {
				return pids[i] < pids[j]
			})
			assert.Equal(t, tc.expectedPids, pids, "expected pIds: %v, found pIds: %v", tc.expectedPids, pids)

			RTProcess.Init(cfg, &model.SystemInfo{})

			// fill in the real-time process cache
			for _, fp := range tc.last {
				fillProcessCache(RTProcess.cache, fp, now.Add(-5*time.Minute).Unix(), now.Unix())
			}

			chunkedStat := RTProcess.fmtProcessStats(cfg, cur, containers, syst2, syst1, lastRun)
			assert.Len(t, chunkedStat, tc.expectedChunks, "len stat %d", i)
			total = 0
			pids = make([]int32, 0)
			for _, c := range chunkedStat {
				total += len(c)
				for _, proc := range c {
					pids = append(pids, proc.Pid)
				}
			}
			assert.Equal(t, tc.expectedTotal, total, "total stat test %d", i)
			sort.Slice(pids, func(i, j int) bool {
				return pids[i] < pids[j]
			})
			assert.Equal(t, tc.expectedPids, pids, "expected pIds: %v, found pIds: %v", tc.expectedPids, pids)
		})
	}

	Process.cache.Flush()
}

func TestPercentCalculation(t *testing.T) {
	// Capping at NUM CPU * 100 if we get odd values for delta-{Proc,Time}
	assert.True(t, floatEquals(calculatePct(100, 50, 1), 100))

	// Zero deltaTime case
	assert.True(t, floatEquals(calculatePct(100, 0, 8), 0.0))

	assert.True(t, floatEquals(calculatePct(0, 8.08, 8), 0.0))
	if runtime.GOOS != "windows" {
		assert.True(t, floatEquals(calculatePct(100, 200, 2), 100))
		assert.True(t, floatEquals(calculatePct(0.04, 8.08, 8), 3.960396))
		assert.True(t, floatEquals(calculatePct(1.09, 8.08, 8), 107.920792))
	}
}

func TestRateCalculation(t *testing.T) {
	now := time.Now()
	prev := now.Add(-1 * time.Second)
	var empty time.Time
	assert.True(t, floatEquals(calculateRate(5, 1, prev), 4))
	assert.True(t, floatEquals(calculateRate(5, 1, prev.Add(-2*time.Second)), float32(1.33333333)))
	assert.True(t, floatEquals(calculateRate(5, 1, now), 0))
	assert.True(t, floatEquals(calculateRate(5, 0, prev), 0))
	assert.True(t, floatEquals(calculateRate(5, 1, empty), 0))
}

func TestProcessCache(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	cfg.ShortLivedProcessQualifierSecs = 500 * time.Millisecond
	cfg.ProcessCacheDurationMin = 600 * time.Millisecond
	var containers []*containers.Container
	lastRun := time.Now().Add(-5 * time.Second)
	syst1, syst2 := cpu.TimesStat{
		User: 10, System: 20, Nice: 0, Iowait: 0, Irq: 0, Softirq: 0, Steal: 0, Guest: 0,
		GuestNice: 0, Idle: 0, Stolen: 0,
	}, cpu.TimesStat{
		User: 20, System: 40, Nice: 0, Iowait: 0, Irq: 0, Softirq: 0, Steal: 0, Guest: 0,
		GuestNice: 0, Idle: 0, Stolen: 0,
	}
	cur := make(map[int32]*process.FilledProcess)
	for _, c := range []*process.FilledProcess{
		// generic processes
		makeProcessWithResource(1, "git clone google.com", 0, 0, 0, 0, 0),
		makeProcessWithResource(2, "mine-bitcoins -all -x", 0, 0, 0, 0, 0),
		makeProcessWithResource(3, "datadog-process-agent -ddconfig datadog.conf", 0, 0, 0, 0, 0),
		makeProcessWithResource(4, "foo -bar -bim", 0, 0, 0, 0, 0),
	} {
		c.CpuTime.Timestamp = 60 * 100 //in Windows uses CPUTime.Timestamp set to now in nanos
		cur[c.Pid] = c
	}

	Process.Init(cfg, &model.SystemInfo{})

	// assert an empty cache.
	assert.Zero(t, Process.cache.ItemCount(), "Cache should be empty before running")

	// first run on an empty cache; expect no process, but cache should be filled in now.
	firstRun := Process.fmtProcesses(cfg, cur, containers, syst2, syst1, lastRun)
	assert.Zero(t, len(firstRun), "Processes should be empty when the cache is not present")
	assert.Equal(t, 4, Process.cache.ItemCount(), "Cache should contain 4 elements")

	// wait for the shortlived qualifier seconds
	time.Sleep(cfg.ShortLivedProcessQualifierSecs)

	// second run with filled in cache; expect all processes.
	secondRun := Process.fmtProcesses(cfg, cur, containers, syst2, syst1, lastRun)
	assert.Equal(t, 4, len(secondRun), "Processes should contain 4 elements")
	assert.Equal(t, 4, Process.cache.ItemCount(), "Cache should contain 4 elements")

	// delete pid 4 from the process map, expect it to be excluded from the process list, but not the cache
	delete(cur, 4)
	thirdRun := Process.fmtProcesses(cfg, cur, containers, syst2, syst1, lastRun)
	assert.Equal(t, 3, len(thirdRun), "Processes should contain 3 elements")
	assert.Equal(t, 4, Process.cache.ItemCount(), "Cache should contain 4 elements")

	// wait for cfg.ProcessCacheDurationMin + a 250 Millisecond buffer to allow the cache expiration to complete
	time.Sleep(cfg.ProcessCacheDurationMin + 250*time.Millisecond)
	assert.Zero(t, Process.cache.ItemCount(), "Cache should be empty again")

	Process.cache.Flush()
}

func TestProcessShortLivedFiltering(t *testing.T) {
	cfg := config.NewDefaultAgentConfig()
	var containers []*containers.Container
	lastRun := time.Now().Add(-5 * time.Second)
	syst1, syst2 := cpu.TimesStat{
		User: 10, System: 20, Nice: 0, Iowait: 0, Irq: 0, Softirq: 0, Steal: 0, Guest: 0,
		GuestNice: 0, Idle: 0, Stolen: 0,
	}, cpu.TimesStat{
		User: 20, System: 40, Nice: 0, Iowait: 0, Irq: 0, Softirq: 0, Steal: 0, Guest: 0,
		GuestNice: 0, Idle: 0, Stolen: 0,
	}
	cur := make(map[int32]*process.FilledProcess)
	for _, c := range []*process.FilledProcess{
		// generic processes
		makeProcessWithResource(1, "git clone google.com", 0, 0, 0, 0, 0),
	} {
		c.CpuTime.Timestamp = 60 * 100 //in Windows uses CPUTime.Timestamp set to now in nanos
		cur[c.Pid] = c
	}

	for _, tc := range []struct {
		name                     string
		prepCache                func(c *cache.Cache)
		expected                 bool
		processShortLivedEnabled bool
	}{
		{
			name: fmt.Sprintf("Should not filter a process that has been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *cache.Cache) {
				fillProcessCache(c, cur[1], lastRun.Add(-5*time.Minute).Unix(), lastRun.Unix())
			},
			expected:                 true,
			processShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should filter a process that has not been observed longer than the short-lived qualifier "+
				"duration: %d", cfg.ShortLivedProcessQualifierSecs),
			prepCache: func(c *cache.Cache) {
				fillProcessCache(c, cur[1], lastRun.Add(-5*time.Second).Unix(), lastRun.Unix())
			},
			expected:                 false,
			processShortLivedEnabled: true,
		},
		{
			name: fmt.Sprintf("Should not filter a process when the processShortLivedEnabled is set to false"),
			prepCache: func(c *cache.Cache) {

				fillProcessCache(c, cur[1], lastRun.Add(-5*time.Second).Unix(), lastRun.Unix())
			},
			expected:                 true,
			processShortLivedEnabled: false,
		},
	} {

		t.Run(tc.name, func(t *testing.T) {
			cfg.EnableShortLivedProcessFilter = tc.processShortLivedEnabled

			// Process Check
			Process.Init(cfg, &model.SystemInfo{})
			tc.prepCache(Process.cache)
			// fill in the process cache
			processes := Process.fmtProcesses(cfg, cur, containers, syst2, syst1, lastRun)
			var pids []string
			for _, p := range processes {
				pids = append(pids, createProcessID(p.Pid, p.CreateTime))
			}

			p := cur[1]
			processID := createProcessID(p.Pid, p.CreateTime)

			if tc.expected {
				assert.Len(t, processes, 1, "Process should be present in the returned payload for the Process Check")
				assert.Contains(t, pids, processID, "%s should not be filtered from the process identifiers for the Process Check", processID)
			} else {
				assert.Len(t, processes, 0, "The process should be filtered in the returned payload for the Process Check")
				assert.NotContains(t, pids, processID, "%s should be filtered from the process identifiers for the Process Check", processID)
			}

			// Process RT Check
			RTProcess.Init(cfg, &model.SystemInfo{})
			// fill in the real-time process cache
			tc.prepCache(RTProcess.cache)

			chunkedStat := RTProcess.fmtProcessStats(cfg, cur, containers, syst2, syst1, lastRun)
			pids = make([]string, 0)
			for _, c := range chunkedStat {
				for _, p := range c {
					pids = append(pids, createProcessID(p.Pid, p.CreateTime))
				}
			}
			if tc.expected {
				assert.Len(t, processes, 1, "Process should be present in the returned payload for the RTProcess Check")
				assert.Contains(t, pids, processID, "%s should not be filtered from the process identifiers for the RTProcess Check", processID)
			} else {
				assert.Len(t, processes, 0, "The process should be filtered in the returned payload for the RTProcess Check")
				assert.NotContains(t, pids, processID, "%s should be filtered from the process identifiers for the RTProcess Check", processID)
			}
		})
	}

	Process.cache.Flush()
	RTProcess.cache.Flush()
}

func floatEquals(a, b float32) bool {
	var e float32 = 0.00000001 // Difference less than some epsilon
	return a-b < e && b-a < e
}

func fillProcessCache(c *cache.Cache, fp *process.FilledProcess, firstObserved, lastObserved int64) {
	processID := createProcessID(fp.Pid, fp.CreateTime)
	cachedProcess := &ProcessCache{
		ProcessMetrics: ProcessMetrics{
			CPUTime: fp.CpuTime,
			IOStat:  fp.IOStat,
		},
		FirstObserved: firstObserved,
		LastObserved:  lastObserved,
	}

	c.Set(processID, cachedProcess, cache.DefaultExpiration)
}
