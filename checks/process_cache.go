package checks

import (
	"github.com/DataDog/gopsutil/process"
	"github.com/patrickmn/go-cache"
	"time"
)

// ProcessCache is used as the struct in the cache for all seen processes
type ProcessCache struct {
	Process       *process.FilledProcess
	FirstObserved int64
	LastObserved  int64
}

func isCached(c *cache.Cache, fp *process.FilledProcess) (*ProcessCache, bool) {
	processID := createProcessID(fp.Pid, fp.CreateTime)

	cPointer, found := c.Get(processID)
	if found {
		return cPointer.(*ProcessCache), true
	}

	return nil, false
}

func putCache(c *cache.Cache, fp *process.FilledProcess) *ProcessCache {
	var cachedProcess *ProcessCache
	processID := createProcessID(fp.Pid, fp.CreateTime)
	nowUnix := time.Now().Unix()

	cPointer, found := c.Get(processID)
	if found {
		cachedProcess = cPointer.(*ProcessCache)
		cachedProcess.Process = fp
		cachedProcess.LastObserved = nowUnix
	} else {
		cachedProcess = &ProcessCache{
			Process:       fp,
			FirstObserved: nowUnix,
			LastObserved:  nowUnix,
		}
	}

	c.Set(processID, cachedProcess, cache.DefaultExpiration)
	return cachedProcess
}
