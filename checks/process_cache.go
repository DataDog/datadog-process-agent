package checks

import (
	"github.com/DataDog/gopsutil/cpu"
	"github.com/DataDog/gopsutil/process"
	"github.com/patrickmn/go-cache"
	"time"
)

// ProcessMetrics is used to keep state of the previous cpu time and io stat counters so that we can calculate usage rate
type ProcessMetrics struct {
	CPUTime cpu.TimesStat
	IOStat  *process.IOCountersStat
}

// ProcessCache is used as the struct in the cache for all seen processes
type ProcessCache struct {
	ProcessMetrics ProcessMetrics
	FirstObserved  int64
	LastObserved   int64
}

// IsProcessCached checks whether the given process ID (pid + pidCreateTime) is present
func IsProcessCached(c *cache.Cache, fp *process.FilledProcess) (*ProcessCache, bool) {
	processID := createProcessID(fp.Pid, fp.CreateTime)

	cPointer, found := c.Get(processID)
	if found {
		return cPointer.(*ProcessCache), true
	}

	return nil, false
}

// PutProcessCache inserts or updates the ProcessCache for a given process ID (pid + pidCreateTime)
func PutProcessCache(c *cache.Cache, fp *process.FilledProcess) *ProcessCache {
	var cachedProcess *ProcessCache
	processID := createProcessID(fp.Pid, fp.CreateTime)
	nowUnix := time.Now().Unix()

	cPointer, found := c.Get(processID)
	if found {
		cachedProcess = cPointer.(*ProcessCache)
		cachedProcess.ProcessMetrics = ProcessMetrics{
			CPUTime: fp.CpuTime,
			IOStat:  fp.IOStat,
		}
		cachedProcess.LastObserved = nowUnix
	} else {
		cachedProcess = &ProcessCache{
			ProcessMetrics: ProcessMetrics{
				CPUTime: fp.CpuTime,
				IOStat:  fp.IOStat,
			},
			FirstObserved: nowUnix,
			LastObserved:  nowUnix,
		}
	}

	c.Set(processID, cachedProcess, cache.DefaultExpiration)
	return cachedProcess
}
