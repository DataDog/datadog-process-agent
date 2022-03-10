package checks

import (
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/patrickmn/go-cache"
	"time"
)

// NetworkRelationCache is used to track age of network relations and to keep metrics for connection for calculating rates
type NetworkRelationCache struct {
	cache *cache.Cache
}

// NewNetworkRelationCache create network relation cache with specified minimum duration for stored items
func NewNetworkRelationCache(minCacheDuration time.Duration) *NetworkRelationCache {
	relationCache := cache.New(minCacheDuration, minCacheDuration)
	return &NetworkRelationCache{
		cache: relationCache,
	}
}

// NetworkRelationCacheItem is used as the struct in the cache for all seen network relations
// The Short-Lived Relations is used to filter out network relations that are observed for less than x seconds, with the default being 60 seconds.
// Short-Lived network relations are defined as network connections that do not occur frequently between processes / services.
// Multiple short-lived connections between the same processes / services are considered a Long-Lived network relation,
// while a once-off network connection is filtered out and not reported to StackState.
// This is done by removing source port from cache key in CreateNetworkRelationIdentifier & createRelationIdentifier in checks/net_common.go
type NetworkRelationCacheItem struct {
	FirstObserved int64
}

// IsNetworkRelationCached checks to see if this relationID is present in the NetworkRelationCacheItem
func (nrc *NetworkRelationCache) IsNetworkRelationCached(relationID string) (*NetworkRelationCacheItem, bool) {
	cPointer, found := nrc.cache.Get(relationID)
	if found {
		return cPointer.(*NetworkRelationCacheItem), true
	}
	return nil, false
}

// PutNetworkRelationCache inserts / updates the NetworkRelationCacheItem for relationID
func (nrc *NetworkRelationCache) PutNetworkRelationCache(relationID string, connStats common.ConnectionStats) *NetworkRelationCacheItem {
	var cachedRelation *NetworkRelationCacheItem
	nowUnix := time.Now().Unix()

	cPointer, found := nrc.cache.Get(relationID)
	if found {
		cachedRelation = cPointer.(*NetworkRelationCacheItem)
	} else {
		cachedRelation = &NetworkRelationCacheItem{
			FirstObserved: nowUnix,
		}
	}

	nrc.cache.Set(relationID, cachedRelation, cache.DefaultExpiration)
	return cachedRelation
}

// Flush removes all items from cache
func (nrc *NetworkRelationCache) Flush() {
	nrc.cache.Flush()
}

// ItemCount returns total number of network relations in the cache
func (nrc *NetworkRelationCache) ItemCount() int {
	return len(nrc.cache.Items())
}
