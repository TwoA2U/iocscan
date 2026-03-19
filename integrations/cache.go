// integrations/cache.go — Cache bridge for integration wrappers.
//
// The getCacheEntry / putCacheEntry helpers live in utils/common.go
// (package utils). Integration wrappers need to call them without
// creating an import cycle (utils → integrations → utils would cycle).
//
// Solution: define function variables here that utils/common.go populates
// at InitDB() time via integrations.SetCacheFuncs(). The wrappers call
// these variables; the implementations stay in utils.
//
// SetCacheFuncs is guarded by sync.Once so it is safe to call from
// concurrent test goroutines and is idempotent after the first call.
package integrations

import "sync"

// CacheGetFn is the signature of getCacheEntry in utils/common.go.
type CacheGetFn func(key, table string) string

// CachePutFn is the signature of putCacheEntry in utils/common.go.
type CachePutFn func(key, data, table string)

var (
	cacheMu       sync.RWMutex
	getCacheEntry CacheGetFn = func(_, _ string) string { return "" }
	putCacheEntry CachePutFn = func(_, _, _ string) {}
	cacheSet      bool
)

// SetCacheFuncs injects the real cache implementations from utils/common.go.
// Must be called before any scan requests are handled (e.g. from InitDB()).
// Safe to call from multiple goroutines — protected by a write lock.
// The no-op defaults ensure integration unit tests never panic.
func SetCacheFuncs(get CacheGetFn, put CachePutFn) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	getCacheEntry = get
	putCacheEntry = put
	cacheSet = true
}

// cachedGet calls the injected get function under a read lock.
func cachedGet(key, table string) string {
	cacheMu.RLock()
	fn := getCacheEntry
	cacheMu.RUnlock()
	return fn(key, table)
}

// cachedPut calls the injected put function under a read lock.
func cachedPut(key, data, table string) {
	cacheMu.RLock()
	fn := putCacheEntry
	cacheMu.RUnlock()
	fn(key, data, table)
}
