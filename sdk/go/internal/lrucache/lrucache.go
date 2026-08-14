// Package lrucache is the one bounded, least-recently-used map the SDK's caching
// tiers share.
//
// Both callers key on a host an incoming offer named, so the key space is
// open-ended and caller-influenced — an unbounded map over one is somewhere an
// authenticated caller can make the process grow without limit. Both therefore
// need the same structure, and having written it twice the second copy carried
// the first's rationale paragraph verbatim. One implementation is what stops an
// eviction fix landing in one and not the other.
//
// Least-recently-used and not drop-the-whole-map: dropping empties the cache
// exactly when it is under most pressure, and it makes which entries survive a
// function of the order a caller names hosts — a property the caller controls.
//
// It is internal on purpose. A bounded map is not a protocol concept, so it has
// no cross-language counterpart to mirror and no business on the SDK's public
// surface.
package lrucache

import (
	"container/list"
	"sync"
)

// Cache holds at most cap entries, evicting the least recently used to make room.
// The zero value is not usable; build one with New.
//
// Safe for concurrent use. Every method takes the same lock, including the loader
// GetOrCreate runs — so a value is constructed exactly once per key even when two
// callers race for it.
type Cache[K comparable, V any] struct {
	cap     int
	mu      sync.Mutex
	order   *list.List // front is most-recently-used; values are *entry[K, V]
	entries map[K]*list.Element
}

// entry is what the recency list holds: the key beside its value, so eviction can
// find the map key from the list element it is dropping.
type entry[K comparable, V any] struct {
	key K
	val V
}

// New returns a cache bounded at cap entries. A cap below one is treated as one:
// a zero-capacity cache would evict what it just stored, which no caller wants and
// which would make every lookup a miss.
func New[K comparable, V any](cap int) *Cache[K, V] {
	if cap < 1 {
		cap = 1
	}
	return &Cache[K, V]{
		cap:     cap,
		order:   list.New(),
		entries: make(map[K]*list.Element, cap),
	}
}

// Get returns the value stored for key and promotes it to most-recently-used.
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*entry[K, V]).val, true
}

// Put stores val for key, promoting it and evicting the least-recently-used entry
// once the cache is full. An existing key is updated in place rather than
// consuming a second slot.
func (c *Cache[K, V]) Put(key K, val V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.put(key, val)
}

// GetOrCreate returns the value stored for key, building it with make on a miss.
//
// make runs under the cache's lock, so a key is built once however many callers
// race. That is deliberate for the callers here — both build cheap in-process
// plumbing, never anything that dials — and it is why this is not a general-purpose
// memoizer.
func (c *Cache[K, V]) GetOrCreate(key K, make func(K) V) V {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[key]; ok {
		c.order.MoveToFront(el)
		return el.Value.(*entry[K, V]).val
	}
	val := make(key)
	c.put(key, val)
	return val
}

// put is the shared insert. The caller holds the lock.
func (c *Cache[K, V]) put(key K, val V) {
	if el, ok := c.entries[key]; ok {
		el.Value.(*entry[K, V]).val = val
		c.order.MoveToFront(el)
		return
	}
	if len(c.entries) >= c.cap {
		if oldest := c.order.Back(); oldest != nil {
			c.order.Remove(oldest)
			delete(c.entries, oldest.Value.(*entry[K, V]).key)
		}
	}
	c.entries[key] = c.order.PushFront(&entry[K, V]{key: key, val: val})
}

// Len reports how many entries the cache holds, and Has whether one is present
// without disturbing recency.
//
// Both exist for the eviction tests. The bound has no observable behaviour of its
// own other than a dial or fetch count, and counting those would mean mocking the
// very transport the suites deliberately never mock.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Has reports whether key is currently held, without promoting it.
func (c *Cache[K, V]) Has(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[key]
	return ok
}
