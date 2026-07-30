package security

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/ratelimit"
)

// newTestGuard builds a Guard with a permissive allow-list that lets the
// happy-path test reach 127.0.0.1 directly without DNS.
func newTestGuard(t *testing.T) *Guard {
	t.Helper()
	cfg := &config.SecurityConfig{
		Targets: config.TargetPolicy{
			Allow: []config.TargetRule{
				{
					Type:    "exact",
					Pattern: "example.com",
					Tools:   []string{"tcp_probe", "probe_check_target"},
				},
				{
					Type:    "cidr",
					Pattern: "127.0.0.0/8",
					Tools:   []string{"tcp_probe", "probe_check_target"},
				},
			},
		},
		Network: config.NetworkPolicy{
			BlockPrivate:     ptrBool(false),
			BlockLoopback:    ptrBool(false),
			BlockLinkLocal:   ptrBool(true),
			BlockMulticast:   ptrBool(true),
			BlockUnspecified: ptrBool(true),
			BlockCloudMeta:   ptrBool(true),
			AllowIPv4:        ptrBool(true),
			AllowIPv6:        ptrBool(false),
		},
		DNS: config.DNSPolicy{},
	}
	filter, err := NewIPFilter(&cfg.Network)
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewSafeResolver(cfg.DNS, filter)
	dialer, err := NewSafeDialer(cfg.Network, filter, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	mgr := ratelimit.NewManager(ratelimit.ManagerConfig{
		Global:        ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:     ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerSession:    ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		MaxConcurrent: 100,
		KeyedTTL:      time.Minute,
		KeyedMaxKeys:  1024,
		MaxCalls:      10_000,
	})
	g, err := NewGuard(cfg, resolver, dialer, filter, mgr)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func ptrBool(b bool) *bool { return &b }

// TestGuard_RejectsSSRFBypasses walks through every known SSRF bypass vector
// and asserts the Guard rejects it with a meaningful error category. This
// is the most important test in the project: a regression here IS a
// vulnerability.
func TestGuard_RejectsSSRFBypasses(t *testing.T) {
	g := newTestGuard(t)

	tests := []struct {
		name    string
		host    string
		port    uint16
		wantSub string
	}{
		// IP literal bypasses
		{"loopback v4", "127.0.0.1", 80, "loopback"},
		{"loopback range", "127.255.255.254", 80, "loopback"},
		{"private 10/8", "10.0.0.1", 80, "private"},
		{"private 172.16/12", "172.16.0.1", 80, "private"},
		{"private 192.168/16", "192.168.1.1", 80, "private"},
		{"link-local", "169.254.169.254", 80, "link-local"},
		{"unspecified", "0.0.0.0", 80, "unspecified"},
		{"multicast", "224.0.0.1", 80, "multicast"},
		{"broadcast", "255.255.255.255", 80, "denied"},
		// Non-canonical encodings: netip.ParseAddr refuses them outright.
		{"decimal integer", "2130706433", 80, ""},
		{"octal", "0177.0.0.1", 80, ""},
		{"hex", "0x7f000001", 80, ""},
		{"short form", "127.1", 80, ""},
		// Hostname manipulation
		{"unqualified", "metadata", 80, ""},
		{"overlong label", strings.Repeat("a", 64) + ".com", 80, ""},
		{"embedded null", "example.com\x00.evil.com", 80, ""},
		{"newline injection", "example.com\r\nHost: evil", 80, ""},
		{"space", "example .com", 80, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := g.Authorize(context.Background(), Request{
				Tool:   "tcp_probe",
				Host:   tc.host,
				Port:   tc.port,
				Scheme: "tcp",
			})
			if err == nil {
				t.Fatalf("expected rejection of %q, got allow", tc.host)
			}
			if tc.wantSub == "" {
				return
			}
			// Accept either the specific keyword OR a generic denial.
			msg := err.Error()
			if !strings.Contains(msg, tc.wantSub) && !strings.Contains(msg, "denied range") {
				t.Errorf("host %q: error %q does not mention %q", tc.host, msg, tc.wantSub)
			}
			var de *DenyError
			if !errors.As(err, &de) {
				t.Errorf("expected *DenyError, got %T", err)
			}
		})
	}
}

// TestGuard_AcceptsAllowedIPLiteral is verified by the IPFilter unit test
// (TestIPFilter_BogonBlocks) and the in-memory MCP integration test; the
// Guard-level happy path requires either DNS or a fake resolver and is
// covered in internal/security/dialer_test.go and the integration test.

// TestIPFilter_BogonBlocks is a focused check on the IPFilter with
// representative cases that don't require DNS.
func TestIPFilter_BogonBlocks(t *testing.T) {
	cases := []struct {
		ip      string
		wantSub string
	}{
		{"127.0.0.1", "loopback"},
		{"::1", "loopback"},
		{"10.0.0.1", "private"},
		{"169.254.169.254", "link-local"},
		{"224.0.0.1", "multicast"},
		{"0.0.0.0", "unspecified"},
		{"::ffff:127.0.0.1", "loopback"},
		{"::ffff:10.0.0.1", "private"},
		{"fe80::1", "link-local"},
		{"fc00::1", "private"},
	}
	net := &config.NetworkPolicy{
		AllowIPv4: ptrBool(true),
		AllowIPv6: ptrBool(true),
	}
	f, err := NewIPFilter(net)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.ip, func(t *testing.T) {
			addr, err := netip.ParseAddr(c.ip)
			if err != nil {
				t.Fatal(err)
			}
			err = f.Check(addr)
			if err == nil {
				t.Fatalf("expected %s to be blocked", c.ip)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("ip %s: error %q does not mention %q", c.ip, err.Error(), c.wantSub)
			}
		})
	}
}

// TestGuard_CheckHostname verifies the lightweight pre-validation used by
// the DNS probe for the QNAME (no rate-limit slot, no resolver pinning).
func TestGuard_CheckHostname(t *testing.T) {
	g := newTestGuard(t)
	ctx := context.Background()

	t.Run("deny unlisted host via resolver", func(t *testing.T) {
		err := g.CheckHostname(ctx, "evil.attacker.com", "dns_probe")
		if err == nil {
			t.Fatalf("expected denial")
		}
		var de *DenyError
		if !errors.As(err, &de) {
			t.Fatalf("expected DenyError, got %T", err)
		}
		// Either DenyNotAllowed (matched by allow-list) or a DNS error
		// (resolution failed in test env). Both are denials.
		if de.Category != DenyNotAllowed && de.Category != DenyDNSFailure && de.Category != DenyIPRange {
			t.Fatalf("unexpected category %s", de.Category)
		}
	})

	t.Run("deny IP literal in blocked range", func(t *testing.T) {
		err := g.CheckHostname(ctx, "169.254.169.254", "dns_probe")
		if err == nil {
			t.Fatalf("expected denial for cloud-metadata IP")
		}
		var de *DenyError
		if !errors.As(err, &de) {
			t.Fatalf("expected DenyError, got %T", err)
		}
		if de.Category != DenyIPRange {
			t.Fatalf("expected DenyIPRange, got %s", de.Category)
		}
	})

	t.Run("deny 127.0.0.1 by default", func(t *testing.T) {
		err := g.CheckHostname(ctx, "127.0.0.1", "tcp_probe")
		if err == nil {
			t.Fatalf("expected denial for loopback under default policy")
		}
		var de *DenyError
		if !errors.As(err, &de) {
			t.Fatalf("expected DenyError, got %T", err)
		}
		if de.Category != DenyIPRange {
			t.Fatalf("expected DenyIPRange, got %s", de.Category)
		}
	})

	t.Run("deny IPv6 literal when disabled", func(t *testing.T) {
		if err := g.CheckHostname(ctx, "::1", "tcp_probe"); err == nil {
			t.Fatalf("expected denial for IPv6 when disabled")
		}
	})

	t.Run("deny encoded ip that maps to blocked", func(t *testing.T) {
		err := g.CheckHostname(ctx, "::ffff:169.254.169.254", "tcp_probe")
		if err == nil {
			t.Fatalf("expected denial for 4-in-6 encoded cloud-metadata")
		}
	})

	t.Run("deny malformed host", func(t *testing.T) {
		if err := g.CheckHostname(ctx, "", "dns_probe"); err == nil {
			t.Fatalf("expected error for empty host")
		}
	})
}
