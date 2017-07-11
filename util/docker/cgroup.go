package docker

import (
	"errors"
	"fmt"
	"math"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-process-agent/util"
)

var (
	containerRe      = regexp.MustCompile("[0-9a-f]{64}")
	ErrMissingTarget = errors.New("Missing cgroup target")
)

type CgroupMemStat struct {
	ContainerID             string
	Cache                   uint64
	RSS                     uint64
	RSSHuge                 uint64
	MappedFile              uint64
	Pgpgin                  uint64
	Pgpgout                 uint64
	Pgfault                 uint64
	Pgmajfault              uint64
	InactiveAnon            uint64
	ActiveAnon              uint64
	InactiveFile            uint64
	ActiveFile              uint64
	Unevictable             uint64
	HierarchicalMemoryLimit uint64
	TotalCache              uint64
	TotalRSS                uint64
	TotalRSSHuge            uint64
	TotalMappedFile         uint64
	TotalPgpgIn             uint64
	TotalPgpgOut            uint64
	TotalPgFault            uint64
	TotalPgMajFault         uint64
	TotalInactiveAnon       uint64
	TotalActiveAnon         uint64
	TotalInactiveFile       uint64
	TotalActiveFile         uint64
	TotalUnevictable        uint64
	MemUsageInBytes         uint64
	MemMaxUsageInBytes      uint64
	MemLimitInBytes         uint64
	MemFailCnt              uint64
}

type CgroupTimesStat struct {
	ContainerID string
	System      float64
	User        float64
}

type CgroupIOStat struct {
	ContainerID string
	ReadBytes   uint64
	WriteBytes  uint64
}

type ContainerCgroup struct {
	ContainerID string
	Pids        []int32
	Paths       map[string]string
	Mounts      map[string]string
}

func (c ContainerCgroup) Mem() (*CgroupMemStat, error) {
	statfile, err := c.cgroupFilePath("memory", "memory.stat")
	if err != nil {
		return nil, err
	}

	lines, err := util.ReadLines(statfile)
	if err != nil {
		return nil, err
	}
	ret := &CgroupMemStat{ContainerID: c.ContainerID}
	for _, line := range lines {
		fields := strings.Split(line, " ")
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "cache":
			ret.Cache = v
		case "rss":
			ret.RSS = v
		case "rssHuge":
			ret.RSSHuge = v
		case "mappedFile":
			ret.MappedFile = v
		case "pgpgin":
			ret.Pgpgin = v
		case "pgpgout":
			ret.Pgpgout = v
		case "pgfault":
			ret.Pgfault = v
		case "pgmajfault":
			ret.Pgmajfault = v
		case "inactiveAnon":
			ret.InactiveAnon = v
		case "activeAnon":
			ret.ActiveAnon = v
		case "inactiveFile":
			ret.InactiveFile = v
		case "activeFile":
			ret.ActiveFile = v
		case "unevictable":
			ret.Unevictable = v
		case "hierarchicalMemoryLimit":
			ret.HierarchicalMemoryLimit = v
		case "totalCache":
			ret.TotalCache = v
		case "totalRss":
			ret.TotalRSS = v
		case "totalRssHuge":
			ret.TotalRSSHuge = v
		case "totalMappedFile":
			ret.TotalMappedFile = v
		case "totalPgpgin":
			ret.TotalPgpgIn = v
		case "totalPgpgout":
			ret.TotalPgpgOut = v
		case "totalPgfault":
			ret.TotalPgFault = v
		case "totalPgmajfault":
			ret.TotalPgMajFault = v
		case "totalInactiveAnon":
			ret.TotalInactiveAnon = v
		case "totalActiveAnon":
			ret.TotalActiveAnon = v
		case "totalInactiveFile":
			ret.TotalInactiveFile = v
		case "totalActiveFile":
			ret.TotalActiveFile = v
		case "totalUnevictable":
			ret.TotalUnevictable = v
		}
	}

	r, err := c.readCgroupMemFile("memory.usage_in_bytes")
	if err == nil {
		ret.MemUsageInBytes = r
	}
	r, err = c.readCgroupMemFile("memory.max_usage_in_bytes")
	if err == nil {
		ret.MemMaxUsageInBytes = r
	}
	r, err = c.readCgroupMemFile("memory.limit_in_bytes")
	if err == nil {
		ret.MemLimitInBytes = r
	}
	r, err = c.readCgroupMemFile("memory.failcnt")
	if err == nil {
		ret.MemFailCnt = r
	}
	return ret, nil
}

// CPU returns the CPU status for this cgroup instance
func (c ContainerCgroup) CPU() (*CgroupTimesStat, error) {
	statfile, err := c.cgroupFilePath("cpuacct", "cpuacct.stat")
	if err != nil {
		return nil, err
	}
	lines, err := util.ReadLines(statfile)
	if err != nil {
		return nil, err
	}
	ret := &CgroupTimesStat{ContainerID: c.ContainerID}
	for _, line := range lines {
		fields := strings.Split(line, " ")
		if fields[0] == "user" {
			user, err := strconv.ParseFloat(fields[1], 64)
			if err == nil {
				ret.User = float64(user)
			}
		}
		if fields[0] == "system" {
			system, err := strconv.ParseFloat(fields[1], 64)
			if err == nil {
				ret.System = float64(system)
			}
		}
	}
	return ret, nil
}

// CPULimit would show CPU limit for this cgroup.
// It does so by checking the cpu period and cpu quota config
// if a user does this:
//
//	docker run --cpus='0.5' ubuntu:latest
//
// we should return 50% for that container
func (c ContainerCgroup) CPULimit() (float64, error) {
	periodFile, err := c.cgroupFilePath("cpu", "cpu.cfs_period_us")
	if err != nil {
		return 0.0, err
	}
	quotaFile, err := c.cgroupFilePath("cpu", "cpu.cfs_quota_us")
	if err != nil {
		return 0.0, err
	}
	plines, err := util.ReadLines(periodFile)
	if err != nil {
		return 0.0, err
	}
	qlines, err := util.ReadLines(quotaFile)
	if err != nil {
		return 0.0, err
	}
	period, err := strconv.ParseFloat(plines[0], 64)
	if err != nil {
		return 0.0, err
	}
	quota, err := strconv.ParseFloat(qlines[0], 64)
	if err != nil {
		return 0.0, err
	}
	// default cpu limit is 100%
	limit := 100.0
	if (period > 0) && (quota > 0) {
		limit = (quota / period) * 100.0
	}
	return limit, nil
}

// IO returns the disk read and write bytes stats for this cgroup.
func (c ContainerCgroup) IO() (*CgroupIOStat, error) {
	statfile, err := c.cgroupFilePath("blkio", "blkio.throttle.io_service_bytes")
	if err != nil {
		return nil, err
	}
	lines, err := util.ReadLines(statfile)
	if err != nil {
		return nil, err
	}
	ret := &CgroupIOStat{ContainerID: c.ContainerID}
	for _, line := range lines {
		fields := strings.Split(line, " ")
		if fields[0] == "Read" {
			read, err := strconv.ParseUint(fields[0], 10, 64)
			if err == nil {
				ret.ReadBytes = read
			}
		}
		if fields[0] == "Write" {
			write, err := strconv.ParseUint(fields[0], 10, 64)
			if err == nil {
				ret.WriteBytes = write
			}
		}
	}
	return ret, nil
}

// cgroupFilePath constructs file path to get targetted stats file.
func (c ContainerCgroup) cgroupFilePath(target, file string) (string, error) {
	mount, ok := c.Mounts[target]
	if !ok {
		return "", fmt.Errorf("missing target %s from mounts", target)
	}
	targetPath, ok := c.Paths[target]
	if !ok {
		return "", fmt.Errorf("missing target %s from paths")
	}

	statfile := filepath.Join(mount, targetPath, file)
	if !util.PathExists(statfile) {
		return "", fmt.Errorf("file not exist: %s", statfile)
	}
	return statfile, nil
}

// readCgroupMemFile reads a memory cgroup file and return the contents as uint64.
func (c ContainerCgroup) readCgroupMemFile(file string) (uint64, error) {
	statfile, err := c.cgroupFilePath("memory", file)
	if err != nil {
		return 0, err
	}
	lines, err := util.ReadLines(statfile)
	if err != nil {
		return 0, err
	}
	if len(lines) != 1 {
		return 0, fmt.Errorf("wrong format file: %s", statfile)
	}
	v, err := strconv.ParseUint(lines[0], 10, 64)
	if err != nil {
		return 0, err
	}
	// limit_in_bytes is a special case here, it's possible that it shows a ridiculous number,
	// in which case it represents unlimited, so return 0 here
	if (file == "memory.limit_in_bytes") && (v > uint64(math.Pow(2, 60))) {
		v = 0
	}
	return v, nil
}

// function to get the mount point of all cgroup. by default it should be under /sys/fs/cgroup but
// it could be mounted anywhere else if manually defined. Example cgroup entries in /proc/mounts would be
//	 cgroup /sys/fs/cgroup/cpuset cgroup rw,relatime,cpuset 0 0
//	 cgroup /sys/fs/cgroup/cpu cgroup rw,relatime,cpu 0 0
//	 cgroup /sys/fs/cgroup/cpuacct cgroup rw,relatime,cpuacct 0 0
//	 cgroup /sys/fs/cgroup/memory cgroup rw,relatime,memory 0 0
//	 cgroup /sys/fs/cgroup/devices cgroup rw,relatime,devices 0 0
//	 cgroup /sys/fs/cgroup/freezer cgroup rw,relatime,freezer 0 0
//	 cgroup /sys/fs/cgroup/blkio cgroup rw,relatime,blkio 0 0
//	 cgroup /sys/fs/cgroup/perf_event cgroup rw,relatime,perf_event 0 0
//	 cgroup /sys/fs/cgroup/hugetlb cgroup rw,relatime,hugetlb 0 0
//
// Returns a map for every target (cpuset, cpu, cpuacct) => path
func cgroupMountPoints() (map[string]string, error) {
	mountsFile := "/proc/mounts"
	if !util.PathExists(mountsFile) {
		return nil, fmt.Errorf("/proc/mounts does not exist")
	}

	// Get all cgroup entries
	lines, err := util.ReadLines(mountsFile)
	if err != nil {
		return nil, err
	}
	return parseCgroupMountPoints(lines), nil
}

func parseCgroupMountPoints(lines []string) map[string]string {
	mounts := []string{}
	for _, l := range lines {
		if strings.HasPrefix(l, "cgroup ") {
			mounts = append(mounts, l)
		}
	}

	// Parse as target => path
	mountPoints := make(map[string]string)
	for _, mount := range mounts {
		tokens := strings.Split(mount, " ")
		// Target can be comma-separate values like cpu,cpuacct
		tsp := strings.Split(path.Base(tokens[1]), ",")
		for _, target := range tsp {
			mountPoints[target] = tokens[1]
		}
	}
	return mountPoints
}

// CgroupsForPids returns ContainerCgroup for every container that's in a Cgroup.
// We return as a map[containerID]Cgroup for easy look-up.
func CgroupsForPids(pids []int32) (map[string]*ContainerCgroup, error) {
	mounts, err := cgroupMountPoints()
	if err != nil {
		return nil, err
	}
	cgs := make(map[string]*ContainerCgroup)
	for _, pid := range pids {
		cgPath := util.HostProc(strconv.Itoa(int(pid)), "cgroup")
		if !util.PathExists(cgPath) {
			continue
		}

		lines, err := util.ReadLines(cgPath)
		if err != nil {
			continue
		}
		if len(lines) == 0 {
			continue
		}
		containerID, paths := parseCgroupPaths(lines)
		if containerID == "" {
			continue
		}

		if cg, ok := cgs[containerID]; ok {
			// Assumes that the paths will always be the same for a container id.
			cg.Pids = append(cg.Pids, pid)
		} else {
			cgs[containerID] = &ContainerCgroup{
				ContainerID: containerID,
				Pids:        []int32{pid},
				Paths:       paths,
				Mounts:      mounts}
		}
	}
	return cgs, nil
}

// CGroup for pid returns a ContainerCgroup for a single pid
func CGroupForPid(pid int32) (*ContainerCgroup, error) {
	mounts, err := cgroupMountPoints()
	if err != nil {
		return nil, err
	}
	cgPath := util.HostProc(strconv.Itoa(int(pid)), "cgroup")
	if !util.PathExists(cgPath) {
		return nil, fmt.Errorf("missing cgroup file for pid %d", pid)
	}

	lines, err := util.ReadLines(cgPath)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty cgroup file for pid %d", pid)
	}
	containerID, paths := parseCgroupPaths(lines)
	if containerID == "" {
		return nil, fmt.Errorf("pid %d not in a container", pid)
	}
	return &ContainerCgroup{
		ContainerID: containerID,
		Pids:        []int32{pid},
		Paths:       paths,
		Mounts:      mounts,
	}, nil
}

// parseCgroupPaths parses out the cgroup paths from a /proc/$pid/cgroup file.
// The file format will be something like:
//
// 11:net_cls:/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e
// 10:freezer:/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e
// 9:cpu,cpuacct:/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e
// 8:memory:/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e
// 7:blkio:/kubepods/besteffort/pod2baa3444-4d37-11e7-bd2f-080027d2bf10/47fc31db38b4fa0f4db44b99d0cad10e3cd4d5f142135a7721c1c95c1aadfb2e
//
// Returns the common containerID and a mapping of target => path
// If the first line doesn't have a valid container ID we will return an empty string
func parseCgroupPaths(lines []string) (string, map[string]string) {
	// Check if this process running inside a container.
	containerID, ok := containerIDFromCgroup(lines[0])
	if !ok {
		return "", nil
	}

	paths := make(map[string]string)
	for _, l := range lines {
		sp := strings.SplitN(l, ":", 3)
		if len(sp) < 3 {
			continue
		}
		// Target can be comma-separate values like cpu,cpuacct
		tsp := strings.Split(sp[1], ",")
		for _, target := range tsp {
			paths[target] = sp[2]
		}
	}

	// In Ubuntu Xenial, we've encountered containers with no `cpu`
	_, cpuok := paths["cpu"]
	cpuacct, cpuacctok := paths["cpuacct"]
	if !cpuok && cpuacctok {
		paths["cpu"] = cpuacct
	}

	return containerID, paths
}

func containerIDFromCgroup(cgroup string) (string, bool) {
	sp := strings.SplitN(cgroup, ":", 3)
	if len(sp) < 3 {
		return "", false
	}
	match := containerRe.Find([]byte(sp[2]))
	if match == nil {
		return "", false
	}
	return string(match), true
}
