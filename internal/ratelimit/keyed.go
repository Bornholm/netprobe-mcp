package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security/errs"
	"golang.org/x/time/rate"
)

// KeyedLimiter is an LRU+TTL map of rate.Limiter keyed by an arbitrary string.
// It is safe for concurrent use and bounds memory with both a maximum number
// of keys and a TTL on last access.
type KeyedLimiter struct {
	name    string
	rps     float64
	burst   int
	ttl     time.Duration
	maxKeys int

	mu      sync.Mutex
	entries map[string]*keyedEntry
	order   *lruOrder
}

type keyedEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
	key      string
	order    *lruElem
}

func NewKeyedLimiter(name string, rps float64, burst int, ttl time.Duration, maxKeys int) *KeyedLimiter {
	return &KeyedLimiter{
		name:    name,
		rps:     rps,
		burst:   burst,
		ttl:     ttl,
		maxKeys: maxKeys,
		entries: make(map[string]*keyedEntry),
		order:   newLRUOrder(),
	}
}

// Acquire reserves a token for key. The returned release function undoes the
// reservation when called immediately after Acquire; for an Allowed result
// it simply no-ops since the token is consumed.
func (k *KeyedLimiter) Acquire(_ context.Context, key string) (func(), error) {
	if key == "" {
		return func() {}, nil
	}
	k.mu.Lock()
	e, ok := k.entries[key]
	if ok {
		k.order.moveToFront(e.order)
		e.lastSeen = time.Now()
	} else {
		k.evictLocked()
		e = &keyedEntry{
			lim:      rate.NewLimiter(rate.Limit(k.rps), k.burst),
			lastSeen: time.Now(),
			key:      key,
		}
		e.order = k.order.pushFront(e)
		k.entries[key] = e
	}
	lim := e.lim
	k.mu.Unlock()

	r := lim.ReserveN(time.Now(), 1)
	if !r.OK() {
		return nil, &errs.DenyError{
			Category: errs.RateLimit,
			Reason:   k.name + " rate limit exceeded",
			Hint:     "retry shortly",
		}
	}
	delay := r.Delay()
	if delay > 0 {
		r.Cancel()
		return nil, &errs.DenyError{
			Category:   errs.RateLimit,
			Reason:     k.name + " rate limit exceeded",
			Hint:       "retry shortly",
			RetryAfter: delay.Round(time.Millisecond),
		}
	}
	return func() { r.Cancel() }, nil
}

func (k *KeyedLimiter) evictLocked() {
	now := time.Now()
	for k.order.tail != nil && now.Sub(k.order.tail.entry.lastSeen) > k.ttl {
		back := k.order.tail
		delete(k.entries, back.entry.key)
		k.order.remove(back)
	}
	for k.order.len() >= k.maxKeys && k.order.tail != nil {
		back := k.order.tail
		delete(k.entries, back.entry.key)
		k.order.remove(back)
	}
}

// EvictIdle forces a sweep; called by the manager's janitor.
func (k *KeyedLimiter) EvictIdle() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.evictLocked()
}

// LRU doubly-linked list.
type lruElem struct {
	entry *keyedEntry
	prev  *lruElem
	next  *lruElem
}

type lruOrder struct {
	head *lruElem
	tail *lruElem
	size int
}

func newLRUOrder() *lruOrder { return &lruOrder{} }

func (l *lruOrder) pushFront(e *keyedEntry) *lruElem {
	n := &lruElem{entry: e}
	if l.head == nil {
		l.head = n
		l.tail = n
	} else {
		n.next = l.head
		l.head.prev = n
		l.head = n
	}
	l.size++
	return n
}

func (l *lruOrder) remove(n *lruElem) {
	if n.prev != nil {
		n.prev.next = n.next
	} else if l.head == n {
		l.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else if l.tail == n {
		l.tail = n.prev
	}
	n.prev = nil
	n.next = nil
	l.size--
}

func (l *lruOrder) moveToFront(n *lruElem) {
	if l.head == n {
		return
	}
	l.remove(n)
	n.prev = nil
	n.next = l.head
	if l.head != nil {
		l.head.prev = n
	}
	l.head = n
	if l.tail == nil {
		l.tail = n
	}
}

func (l *lruOrder) len() int { return l.size }
