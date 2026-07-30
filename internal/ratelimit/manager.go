package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security/errs"
	"golang.org/x/time/rate"
)

// Manager applies four independent rate limit levels:
//  1. session quota (absolute call counter, prevents infinite loops)
//  2. per-tool token bucket
//  3. global token bucket
//  4. per-target keyed token bucket (LRU+TTL)
//  5. concurrency semaphore (single global)
type Manager struct {
	cfg ManagerConfig

	global     *rate.Limiter
	perTool    map[string]*rate.Limiter
	perToolMu  sync.Mutex
	perTarget  *KeyedLimiter
	perSession *KeyedLimiter
	quota      *SessionQuota
	sem        *Semaphore
}

type ManagerConfig struct {
	Global        RateLimit
	PerTool       map[string]RateLimit
	PerTarget     RateLimit
	PerSession    RateLimit
	MaxConcurrent int
	KeyedTTL      time.Duration
	KeyedMaxKeys  int
	MaxCalls      int
}

type RateLimit struct {
	RPS   float64
	Burst int
}

func NewManager(cfg ManagerConfig) *Manager {
	m := &Manager{
		cfg:        cfg,
		global:     rate.NewLimiter(rate.Limit(cfg.Global.RPS), cfg.Global.Burst),
		perTool:    make(map[string]*rate.Limiter, len(cfg.PerTool)),
		perTarget:  NewKeyedLimiter("per_target", cfg.PerTarget.RPS, cfg.PerTarget.Burst, cfg.KeyedTTL, cfg.KeyedMaxKeys),
		perSession: NewKeyedLimiter("per_session", cfg.PerSession.RPS, cfg.PerSession.Burst, cfg.KeyedTTL, cfg.KeyedMaxKeys),
		quota:      NewSessionQuota(cfg.MaxCalls, cfg.KeyedTTL),
		sem:        NewSemaphore(cfg.MaxConcurrent),
	}
	for tool, rl := range cfg.PerTool {
		m.perTool[tool] = rate.NewLimiter(rate.Limit(rl.RPS), rl.Burst)
	}
	return m
}

// Acquire reserves a slot across all four limiters; the returned release
// function must be called even if the probe itself fails, so that resources
// (in particular the concurrency semaphore) are returned.
func (m *Manager) Acquire(ctx context.Context, key errs.RateKey) (release func(), err error) {
	releases := make([]func(), 0, 5)
	rollback := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}

	// 1. Session quota.
	if !m.quota.Allow(key.SessionID) {
		rollback()
		return nil, &errs.DenyError{
			Category: errs.Quota,
			Reason:   "session call quota exhausted",
			Hint:     "wait for the session to end or restart",
		}
	}
	quotaRelease := func() {} // quota is consumed, not released
	releases = append(releases, quotaRelease)

	// 2. Per-tool bucket.
	if lim, ok := m.limiterForTool(key.Tool); ok {
		if err := m.allow(lim, "tool"); err != nil {
			rollback()
			return nil, err
		}
		releases = append(releases, func() {})
	}

	// 3. Global bucket.
	if err := m.allow(m.global, "global"); err != nil {
		rollback()
		return nil, err
	}
	releases = append(releases, func() {})

	// 4. Per-target bucket.
	if rel, err := m.perTarget.Acquire(ctx, key.Target); err != nil {
		rollback()
		return nil, err
	} else if rel != nil {
		releases = append(releases, rel)
	}

	// 5. Per-session bucket.
	if rel, err := m.perSession.Acquire(ctx, key.SessionID); err != nil {
		rollback()
		return nil, err
	} else if rel != nil {
		releases = append(releases, rel)
	}

	// 6. Concurrency semaphore (try-only, never blocks).
	rel, err := m.sem.TryAcquire()
	if err != nil {
		rollback()
		return nil, err
	}
	releases = append(releases, rel)

	combined := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	return combined, nil
}

// allow reserves one token from a non-blocking rate.Limiter. If the token
// would require waiting, we refuse immediately with a RetryAfter hint rather
// than block a worker.
func (m *Manager) allow(lim *rate.Limiter, name string) error {
	r := lim.ReserveN(time.Now(), 1)
	if !r.OK() {
		return &errs.DenyError{
			Category: errs.RateLimit,
			Reason:   fmt.Sprintf("%s rate limit exceeded", name),
			Hint:     "retry shortly",
		}
	}
	delay := r.Delay()
	if delay > 0 {
		r.Cancel()
		de := &errs.DenyError{
			Category:   errs.RateLimit,
			Reason:     fmt.Sprintf("%s rate limit exceeded", name),
			Hint:       "retry shortly",
			RetryAfter: delay.Round(time.Millisecond),
		}
		return de.WithInternal(errors.New("retry-after"))
	}
	return nil
}

func (m *Manager) limiterForTool(tool string) (*rate.Limiter, bool) {
	m.perToolMu.Lock()
	defer m.perToolMu.Unlock()
	l, ok := m.perTool[tool]
	return l, ok
}

// StartJanitor launches a background goroutine that evicts idle keyed limiter
// entries. The goroutine exits when ctx is canceled.
func (m *Manager) StartJanitor(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.perTarget.EvictIdle()
				m.perSession.EvictIdle()
				m.quota.Sweep()
			}
		}
	}()
}

// Compile-time interface check.
var _ errs.Limiter = (*Manager)(nil)
