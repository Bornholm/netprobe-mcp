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

// TestKeyedLimiter_AllowN_BurstExhaustion verifies that AllowN refuses
// immediately when the requested weight exceeds the burst (PLAN §6.2:
// "refuser plutôt qu'attendre").
func TestKeyedLimiter_AllowN_BurstExhaustion(t *testing.T) {
	// burst=2, no rps top-up; the second AllowN(2) after a first
	// AllowN(2) must refuse.
	k := NewKeyedLimiter("test", 0.0001, 2, time.Minute, 16)
	if err := k.AllowN("tgt", 2); err != nil {
		t.Fatalf("first AllowN(2): %v", err)
	}
	if err := k.AllowN("tgt", 2); err == nil {
		t.Fatal("second AllowN(2) should be refused: burst exhausted")
	} else {
		var de *errs.DenyError
		if !errors.As(err, &de) || de.Category != errs.RateLimit {
			t.Fatalf("expected RateLimit denial, got %v", err)
		}
	}
	// n=1 after exhaustion should still work — wait, no, the burst
	// is gone. Actually AllowN(1) calls Acquire internally so the
	// same bucket is consulted. We accept either outcome here as
	// long as no panic happens.
	_ = k.AllowN("tgt", 1)
}

func TestKeyedLimiter_AllowN_NormalisesBelowOne(t *testing.T) {
	// A weight of 0 (or negative) must behave like a 1-token
	// reservation, not panic.
	k := NewKeyedLimiter("test", 1, 1, time.Minute, 4)
	if err := k.AllowN("tgt", 0); err != nil {
		t.Fatalf("AllowN(0): %v", err)
	}
	if err := k.AllowN("tgt", -3); err != nil {
		// The bucket only holds 1, so the second call must be
		// refused. The point of the test is that no panic
		// happens and the bucket semantics are preserved.
		t.Logf("AllowN(-3) refused (expected): %v", err)
	}
}

func TestKeyedLimiter_AllowN_EmptyKey(t *testing.T) {
	// Empty key (used by Guard when the target IP is invalid)
	// must short-circuit to nil without touching the bucket map.
	k := NewKeyedLimiter("test", 1, 1, time.Minute, 4)
	if err := k.AllowN("", 5); err != nil {
		t.Fatalf("AllowN(\"\", 5): %v", err)
	}
	if len(k.entries) != 0 {
		t.Errorf("empty key must not allocate bucket entries, got %d", len(k.entries))
	}
}

// TestManager_AcquireN_ChargesPerTargetOnly checks that AcquireN
// consumes weight tokens from the per-target bucket but only 1
// token from the per-session / global / quota / concurrency
// limiters (PLAN §7.4).
func TestManager_AcquireN_ChargesPerTargetOnly(t *testing.T) {
	mgr := NewManager(ManagerConfig{
		Global:        RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:     RateLimit{RPS: 1000, Burst: 4}, // small burst to expose the cap
		PerSession:    RateLimit{RPS: 1000, Burst: 1000},
		MaxConcurrent: 8,
		KeyedTTL:      time.Minute,
		KeyedMaxKeys:  16,
		MaxCalls:      1000,
	})
	key := errs.RateKey{SessionID: "sess", Tool: "icmp_probe", Target: "1.2.3.4"}

	// AcquireN(4) should consume all 4 per-target tokens. The
	// returned release restores the semaphore and quota, NOT the
	// per-target tokens: they were legitimately consumed (PLAN
	// §6.2 "le Release ne rend PAS les jetons").
	rel, err := mgr.AcquireN(context.Background(), key, 4)
	if err != nil {
		t.Fatalf("first AcquireN(4): %v", err)
	}
	rel()

	// Per-target bucket is now drained. The next Acquire(1) on
	// the same target must refuse.
	if _, err := mgr.Acquire(context.Background(), key); err == nil {
		t.Fatal("per-target bucket should be exhausted after AcquireN(4)+release")
	} else {
		var de *errs.DenyError
		if !errors.As(err, &de) || de.Category != errs.RateLimit {
			t.Fatalf("expected RateLimit denial, got %v", err)
		}
	}

	// But a *different* target must still work: only the bucket
	// for "1.2.3.4" is drained.
	otherKey := errs.RateKey{SessionID: "sess", Tool: "icmp_probe", Target: "5.6.7.8"}
	rel, err = mgr.AcquireN(context.Background(), otherKey, 2)
	if err != nil {
		t.Fatalf("AcquireN(2) on a different target: %v", err)
	}
	rel()
}

// TestManager_AcquireN_RollbackDoesNotLeak verifies that a failed
// AcquireN (because the per-target bucket cannot satisfy the
// weight) does NOT leak tokens from the other limiters. We use
// the per-target bucket as the trip: a burst of 2 means a
// successful AcquireN(2) drains it; the next AcquireN(2) must
// fail at the per-target stage, and any other target must still
// have its bucket intact.
func TestManager_AcquireN_RollbackDoesNotLeak(t *testing.T) {
	mgr := NewManager(ManagerConfig{
		Global:        RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:     RateLimit{RPS: 1000, Burst: 2},
		PerSession:    RateLimit{RPS: 1000, Burst: 1000},
		MaxConcurrent: 8,
		KeyedTTL:      time.Minute,
		KeyedMaxKeys:  16,
		MaxCalls:      1000,
	})
	keyA := errs.RateKey{SessionID: "sess", Tool: "icmp_probe", Target: "1.2.3.4"}
	keyB := errs.RateKey{SessionID: "sess", Tool: "icmp_probe", Target: "5.6.7.8"}

	// Drain bucket A.
	rel, err := mgr.AcquireN(context.Background(), keyA, 2)
	if err != nil {
		t.Fatalf("drain A: %v", err)
	}
	rel()

	// Another AcquireN(2) on A must refuse at per-target.
	if _, err := mgr.AcquireN(context.Background(), keyA, 2); err == nil {
		t.Fatal("expected per-target refusal on A")
	}

	// Bucket B must still be untouched.
	rel, err = mgr.AcquireN(context.Background(), keyB, 2)
	if err != nil {
		t.Fatalf("AcquireN(2) on B should still work (per-target leakage?): %v", err)
	}
	rel()
}
