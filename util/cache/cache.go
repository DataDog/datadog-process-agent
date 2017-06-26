package cache

import (
	"sync"
	"time"
)

var globalCache *memoryCache

// SetWithTTL sets a value in the global memory cache with a TTL.
func SetWithTTL(key string, val interface{}, ttl time.Duration) {
	ensureGlobalCache()
	expiry := time.Now().Add(ttl)
	globalCache.setWithExpiry(key, val, expiry)
}

// Set sets a value in the cache without a TTL
func Set(key string, val interface{}) {
	ensureGlobalCache()
	globalCache.set(key, val)
}

// Get gets a value from the global memory cache. If the value is
// missing or the TTL has passed then it will return (nil, false).
func Get(key string) (interface{}, bool) {
	ensureGlobalCache()
	return globalCache.get(key)
}

// Memory cache is a simple thread-safe in-memory cache.
type memoryCache struct {
	cache  map[string]interface{}
	expiry map[string]time.Time
	sync.Mutex
}

func newMemoryCache() *memoryCache {
	return &memoryCache{
		cache:  make(map[string]interface{}),
		expiry: make(map[string]time.Time)}
}

func (c *memoryCache) set(key string, val interface{}) {
	c.Lock()
	defer c.Unlock()
	c.cache[key] = val
}

func (c *memoryCache) setWithExpiry(key string, val interface{}, expiry time.Time) {
	c.Lock()
	defer c.Unlock()
	c.cache[key] = val
	c.expiry[key] = expiry
}

func (c *memoryCache) get(key string) (interface{}, bool) {
	c.Lock()
	defer c.Unlock()
	// Check if the value is expired
	e, ok := c.expiry[key]
	if ok && e.Before(time.Now()) {
		delete(c.cache, key)
		return nil, false
	}
	v, ok := c.cache[key]
	return v, ok
}

func ensureGlobalCache() {
	if globalCache == nil {
		globalCache = newMemoryCache()
	}
}
