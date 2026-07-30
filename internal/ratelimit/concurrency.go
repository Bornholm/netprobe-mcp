package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security/errs"
)

// Semaphore is a non-blocking weighted semaphore with a fixed capacity.
// TryAcquire refuses immediately when no slot is available; the returned
// release function is idempotent.
type Semaphore struct {
	capacity int64
	held     atomic.Int64
	mu       sync.Mutex
	ch       chan struct{}
}

func NewSemaphore(capacity int) *Semaphore {
	if capacity <= 0 {
		capacity = 1
	}
	return &Semaphore{
		capacity: int64(capacity),
		ch:       make(chan struct{}, capacity),
	}
}

func (s *Semaphore) TryAcquire() (func(), error) {
	if s.held.Add(1) > s.capacity {
		s.held.Add(-1)
		return nil, &errs.DenyError{
			Category: errs.Concurrency,
			Reason:   "server is at maximum concurrent probe capacity",
			Hint:     "retry shortly",
		}
	}
	s.mu.Lock()
	s.ch <- struct{}{}
	s.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			<-s.ch
			s.mu.Unlock()
			s.held.Add(-1)
		})
	}, nil
}

// SessionQuota caps the absolute number of calls per session within a TTL.
// Unlike a token bucket it cannot be filled back up — once exhausted, the
// session is done.
type SessionQuota struct {
	mu       sync.Mutex
	maxCalls int
	ttl      time.Duration
	counters map[string]*sessionCounter
}

type sessionCounter struct {
	calls    int
	lastSeen time.Time
}

func NewSessionQuota(maxCalls int, ttl time.Duration) *SessionQuota {
	return &SessionQuota{
		maxCalls: maxCalls,
		ttl:      ttl,
		counters: make(map[string]*sessionCounter),
	}
}

func (s *SessionQuota) Allow(sessionID string) bool {
	if sessionID == "" {
		return true // unknown session: skip quota
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.counters[sessionID]
	if !ok {
		s.counters[sessionID] = &sessionCounter{calls: 1, lastSeen: time.Now()}
		return true
	}
	c.lastSeen = time.Now()
	if c.calls >= s.maxCalls {
		return false
	}
	c.calls++
	return true
}

func (s *SessionQuota) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-s.ttl)
	for k, c := range s.counters {
		if c.lastSeen.Before(cutoff) {
			delete(s.counters, k)
		}
	}
}
