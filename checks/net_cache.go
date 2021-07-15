package checks

import (
	"fmt"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/common"
	"github.com/patrickmn/go-cache"
	"time"
)

// NetworkRelationCache is used to track age of network relations and to keep metrics for connection for calculating rates
type NetworkRelationCache struct {
	cache            *cache.Cache
	minCacheDuration time.Duration
}

// NewNetworkRelationCache create network relation cache with specified minimum duration for stored items
func NewNetworkRelationCache(minCacheDuration time.Duration) *NetworkRelationCache {
	relationCache := cache.New(minCacheDuration, minCacheDuration)
	return &NetworkRelationCache{
		cache: relationCache,
	}
}

// ConnectionMetrics is used to keep state of the previous send and received bytes so that we can calculate transfer rate
type ConnectionMetrics struct {
	LastObserved int64
	SendBytes    uint64
	RecvBytes    uint64
}

// NetworkRelationCacheItem is used as the struct in the cache for all seen network relations
// The Short-Lived Relations is used to filter out network relations that are observed for less than x seconds, with the default being 60 seconds.
// Short-Lived network relations are defined as network connections that do not occur frequently between processes / services.
// Multiple short-lived connections between the same processes / services are considered a Long-Lived network relation,
// while a once-off network connection is filtered out and not reported to StackState.
// This is done by removing source port from cache key in CreateNetworkRelationIdentifier & createRelationIdentifier in checks/net_common.go
type NetworkRelationCacheItem struct {
	FirstObserved     int64
	LastObserved      int64
	connectionMetrics *cache.Cache
}

// GetMetrics return metrics for particular network connection (not relation)
func (nrci *NetworkRelationCacheItem) GetMetrics(connID common.ConnTuple) (*ConnectionMetrics, bool) {
	result, found := nrci.connectionMetrics.Get(fmt.Sprintf("%v", connID))
	if found {
		return result.(*ConnectionMetrics), true
	}
	return nil, false
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
		cachedRelation.connectionMetrics.Set(
			fmt.Sprintf("%v", connStats.GetConnection()),
			&ConnectionMetrics{
				LastObserved: nowUnix,
				SendBytes:    connStats.SendBytes,
				RecvBytes:    connStats.RecvBytes,
			},
			cache.DefaultExpiration,
		)
		cachedRelation.LastObserved = nowUnix
	} else {
		connCache := cache.New(nrc.minCacheDuration, nrc.minCacheDuration)
		connCache.Set(
			fmt.Sprintf("%v", connStats.GetConnection()),
			&ConnectionMetrics{
				LastObserved: nowUnix,
				SendBytes:    connStats.SendBytes,
				RecvBytes:    connStats.RecvBytes,
			},
			cache.DefaultExpiration,
		)
		cachedRelation = &NetworkRelationCacheItem{
			connectionMetrics: connCache,
			FirstObserved:     nowUnix,
			LastObserved:      nowUnix,
		}
	}

	nrc.cache.Set(relationID, cachedRelation, cache.DefaultExpiration)
	return cachedRelation
}

// Flush removes all items from cache
func (nrc *NetworkRelationCache) Flush() {
	nrc.cache.Flush()
}

// ItemCount returns count of network relations in cache
func (nrc *NetworkRelationCache) ItemCount() int {
	return nrc.cache.ItemCount()
}
