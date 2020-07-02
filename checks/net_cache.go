package checks

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/patrickmn/go-cache"
	"time"
)

// ConnectionMetrics is used to keep state of the previous send and received bytes so that we can calculate transfer rate
type ConnectionMetrics struct {
	SendBytes uint64
	RecvBytes uint64
}

// NetworkRelationCache is used as the struct in the cache for all seen network relations
// The Short-Lived Relations is used to filter out network relations that are observed for less than x seconds, with the default being 60 seconds.
// Short-Lived network relations are defined as network connections that do not occur frequently between processes / services.
// Multiple short-lived connections between the same processes / services are considered a Long-Lived network relation,
// while a once-off network connection is filtered out and not reported to StackState.
type NetworkRelationCache struct {
	ConnectionMetrics ConnectionMetrics
	FirstObserved     int64
	LastObserved      int64
}

// IsNetworkRelationCached checks to see if this relationID is present in the NetworkRelationCache
func IsNetworkRelationCached(c *cache.Cache, relationID string) (*NetworkRelationCache, bool) {
	cPointer, found := c.Get(relationID)
	if found {
		return cPointer.(*NetworkRelationCache), true
	}

	return nil, false
}

// PutNetworkRelationCache inserts / updates the NetworkRelationCache for relationID
func PutNetworkRelationCache(c *cache.Cache, relationID string, connStats common.ConnectionStats) *NetworkRelationCache {
	var cachedRelation *NetworkRelationCache
	nowUnix := time.Now().Unix()

	cPointer, found := c.Get(relationID)
	if found {
		cachedRelation = cPointer.(*NetworkRelationCache)
		cachedRelation.ConnectionMetrics = ConnectionMetrics{
			SendBytes: connStats.SendBytes,
			RecvBytes: connStats.RecvBytes,
		}
		cachedRelation.LastObserved = nowUnix
	} else {
		cachedRelation = &NetworkRelationCache{
			ConnectionMetrics: ConnectionMetrics{
				SendBytes: connStats.SendBytes,
				RecvBytes: connStats.RecvBytes,
			},
			FirstObserved: nowUnix,
			LastObserved:  nowUnix,
		}
	}

	c.Set(relationID, cachedRelation, cache.DefaultExpiration)
	return cachedRelation
}
