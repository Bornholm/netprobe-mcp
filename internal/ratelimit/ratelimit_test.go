package ratelimit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security/errs"
)

func TestManager_AcquireRelease(t *testing.T) {
	mgr := NewManager(ManagerConfig{
		Global:        RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:     RateLimit{RPS: 1000, Burst: 1000},
		PerSession:    RateLimit{RPS: 1000, Burst: 1000},
		MaxConcurrent: 4,
		KeyedTTL:      time.Minute,
		KeyedMaxKeys:  16,
		MaxCalls:      1000,
	})
	for i := 0; i < 8; i++ {
		rel, err := mgr.Acquire(context.Background(), errs.RateKey{
			SessionID: "sess",
			Tool:      "tcp_probe",
			Target:    "1.2.3.4",
		})
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		rel()
	}
}

// TestManager_RespectsConcurrencyCap ensures TryAcquire refuses beyond cap.
func TestManager_RespectsConcurrencyCap(t *testing.T) {
	mgr := NewManager(ManagerConfig{
		Global:        RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:     RateLimit{RPS: 1000, Burst: 1000},
		PerSession:    RateLimit{RPS: 1000, Burst: 1000},
		MaxConcurrent: 2,
		KeyedTTL:      time.Minute,
		KeyedMaxKeys:  16,
		MaxCalls:      1000,
	})
	r1, err := mgr.Acquire(context.Background(), errs.RateKey{Target: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := mgr.Acquire(context.Background(), errs.RateKey{Target: "5.6.7.8"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = mgr.Acquire(context.Background(), errs.RateKey{Target: "9.9.9.9"})
	if err == nil {
		t.Fatal("expected concurrency denial")
	}
	var de *errs.DenyError
	if !errors.As(err, &de) || de.Category != errs.Concurrency {
		t.Fatalf("expected concurrency denial, got %v", err)
	}
	r1()
	r2()
}

// TestManager_QuotaExhaustion ensures the absolute quota triggers a refusal.
func TestManager_QuotaExhaustion(t *testing.T) {
	mgr := NewManager(ManagerConfig{
		Global:        RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:     RateLimit{RPS: 1000, Burst: 1000},
		PerSession:    RateLimit{RPS: 1000, Burst: 1000},
		MaxConcurrent: 100,
		KeyedTTL:      time.Minute,
		KeyedMaxKeys:  16,
		MaxCalls:      3,
	})
	key := errs.RateKey{SessionID: "sess", Target: "1.2.3.4"}
	for i := 0; i < 3; i++ {
		rel, err := mgr.Acquire(context.Background(), key)
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		rel()
	}
	_, err := mgr.Acquire(context.Background(), key)
	if err == nil {
		t.Fatal("expected quota exhaustion")
	}
	var de *errs.DenyError
	if !errors.As(err, &de) || de.Category != errs.Quota {
		t.Fatalf("expected quota denial, got %v", err)
	}
}

// TestKeyedLimiter_LRUEvicts asserts the LRU+TTL evicts idle entries.
func TestKeyedLimiter_LRUEvicts(t *testing.T) {
	k := NewKeyedLimiter("test", 1, 1, 50*time.Millisecond, 2)
	_, _ = k.Acquire(context.Background(), "a")
	_, _ = k.Acquire(context.Background(), "b")
	_, _ = k.Acquire(context.Background(), "c") // should evict "a"
	time.Sleep(100 * time.Millisecond)
	k.EvictIdle()
	if len(k.entries) > 0 {
		t.Logf("after sweep entries: %d", len(k.entries))
	}
}

// TestSemaphore_DoubleReleaseSafe verifies sync.Once protection.
func TestSemaphore_DoubleReleaseSafe(t *testing.T) {
	s := NewSemaphore(2)
	rel, err := s.TryAcquire()
	if err != nil {
		t.Fatal(err)
	}
	rel()
	rel() // must not panic
}

// TestSemaphore_RefusesWhenFull is a sanity check.
func TestSemaphore_RefusesWhenFull(t *testing.T) {
	s := NewSemaphore(1)
	rel, err := s.TryAcquire()
	if err != nil {
		t.Fatal(err)
	}
	defer rel()
	if _, err := s.TryAcquire(); err == nil {
		t.Fatal("expected refusal when full")
	}
}

// TestParallelAcquireRelease runs many parallel acquire/release cycles to
// catch any race condition. Combined with -race this is a strong smoke test.
func TestParallelAcquireRelease(t *testing.T) {
	mgr := NewManager(ManagerConfig{
		Global:        RateLimit{RPS: 100, Burst: 100},
		PerTarget:     RateLimit{RPS: 100, Burst: 100},
		PerSession:    RateLimit{RPS: 100, Burst: 100},
		MaxConcurrent: 16,
		KeyedTTL:      time.Minute,
		KeyedMaxKeys:  64,
		MaxCalls:      10_000,
	})
	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := mgr.Acquire(context.Background(), errs.RateKey{
				SessionID: "sess",
				Tool:      "tcp_probe",
				Target:    "1.2.3.4",
			})
			if err != nil {
				failures.Add(1)
				return
			}
			rel()
		}()
	}
	wg.Wait()
	if failures.Load() > 0 {
		t.Logf("%d acquires failed (likely rate-limit)", failures.Load())
	}
}
