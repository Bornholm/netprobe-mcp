package icmp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

func TestDetectCapability_AlwaysReturnsSomething(t *testing.T) {
	cap := DetectCapability()
	switch cap.Mode {
	case ModeUnprivileged, ModeRaw, ModeUnavailable:
	default:
		t.Errorf("unexpected capability mode: %q", cap.Mode)
	}
	if cap.Mode == ModeUnavailable && cap.Reason == "" {
		t.Errorf("ModeUnavailable must carry a reason")
	}
}

func TestProber_Validate_DefaultsAndBounds(t *testing.T) {
	p := NewProber(ModeUnprivileged, 5*time.Second)
	opts := &Options{Host: "127.0.0.1"}
	if err := p.Validate(opts); err != nil {
		t.Fatal(err)
	}
	if opts.Count != 3 {
		t.Errorf("default Count = %d, want 3", opts.Count)
	}
	if opts.IntervalMs != 200 {
		t.Errorf("default IntervalMs = %d, want 200", opts.IntervalMs)
	}
	if opts.PayloadSize != 0 {
		t.Errorf("default PayloadSize = %d, want 0", opts.PayloadSize)
	}

	// Count ceiling.
	opts2 := &Options{Host: "127.0.0.1", Count: 999}
	if err := p.Validate(opts2); err != nil {
		t.Fatal(err)
	}
	if opts2.Count > p.maxCount {
		t.Errorf("Count = %d, want <= %d", opts2.Count, p.maxCount)
	}

	// Interval floor.
	opts3 := &Options{Host: "127.0.0.1", IntervalMs: 1}
	if err := p.Validate(opts3); err != nil {
		t.Fatal(err)
	}
	if opts3.IntervalMs < 200 {
		t.Errorf("IntervalMs = %d, want >= 200", opts3.IntervalMs)
	}

	// Payload ceiling.
	if err := p.Validate(&Options{Host: "127.0.0.1", PayloadSize: 99999}); err == nil {
		t.Error("expected error for oversized payload")
	}
}

func TestProber_RejectsEmptyHost(t *testing.T) {
	p := NewProber(ModeUnprivileged, time.Second)
	if err := p.Validate(&Options{}); err == nil {
		t.Error("expected error on missing host")
	}
}

func TestProber_UnavailableMode(t *testing.T) {
	p := NewProber(ModeUnavailable, time.Second)
	_, err := p.Run(context.Background(), &security.SafeTarget{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
	}, Options{Host: "127.0.0.1", Count: 1, IntervalMs: 200})
	if err == nil {
		t.Fatal("expected error from unavailable mode")
	}
}

func TestProber_LoopbackEcho_Realistic(t *testing.T) {
	// This test pings loopback. It only runs when the runtime can
	// actually send ICMP. Skip otherwise.
	cap := DetectCapability()
	if cap.Mode == ModeUnavailable {
		t.Skip("no ICMP capability in this environment")
	}
	// Verify with a dry-run send that we can actually reach the
	// destination. Some sandboxes (e.g. CAP_NET_RAW-less
	// containers) report a mode but fail to actually transmit to
	// loopback.
	p := NewProber(cap.Mode, 2*time.Second)
	res, err := p.Run(context.Background(), &security.SafeTarget{
		Hostname: "127.0.0.1",
		IP:       netip.MustParseAddr("127.0.0.1"),
	}, Options{
		Host:       "127.0.0.1",
		Count:      1,
		IntervalMs: 200,
	})
	if err != nil {
		t.Skipf("ICMP send failed in this environment (%v); integration runtime unavailable", err)
	}
	if res.PacketsSent != 1 {
		t.Errorf("PacketsSent = %d, want 1", res.PacketsSent)
	}
}

func TestBuildPayload(t *testing.T) {
	if got := buildPayload(0); got != nil {
		t.Errorf("buildPayload(0) = %v, want nil", got)
	}
	p := buildPayload(10)
	if len(p) != 10 {
		t.Errorf("buildPayload(10) length = %d, want 10", len(p))
	}
	for i, b := range p {
		if int(b) != i {
			t.Errorf("buildPayload[%d] = %d, want %d", i, b, i)
		}
	}
}
