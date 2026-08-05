package security

import (
	"errors"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/ratelimit"
)

func TestCompilePathPattern(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"exact path", "/health", false},
		{"label glob", "/v1/*", false},
		{"cross-label glob", "/v1/**", false},
		{"anchored glob", "/api/**/status", false},
		{"empty rejected", "", true},
		{"no leading slash rejected", "health", true},
		{"double star twice rejected", "/v1/**/**", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compilePathPattern(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("compilePathPattern(%q): err=%v wantErr=%v", tc.in, err, tc.wantErr)
			}
		})
	}
}

func TestPathMatcher_Match(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		// exact
		{"/health", "/health", true},
		{"/health", "/Health", false}, // paths are case-sensitive
		{"/health", "/health/", false},
		{"/health", "/health/sub", false},

		// single-label glob
		{"/v1/*", "/v1/status", true},
		{"/v1/*", "/v1/users/42", false}, // '*' must not cross '/'
		{"/v1/*", "/v2/status", false},

		// double-label glob
		{"/v1/**", "/v1/status", true},
		{"/v1/**", "/v1/users/42/admin", true},
		{"/v1/**", "/v2/status", false},

		// anchored glob
		{"/api/**/status", "/api/v1/status", true},
		{"/api/**/status", "/api/v1/users/status", true},
		{"/api/**/status", "/api/v1/statusX", false},
		{"/api/**/status", "/api/status", true}, // '**' matches zero segments too
	}
	for _, tc := range cases {
		t.Run(tc.pattern+"_"+tc.path, func(t *testing.T) {
			pm, err := compilePathPattern(tc.pattern)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got := pm.Match(tc.path)
			if got != tc.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
			}
		})
	}
}

// newGuardWithAllow builds a Guard whose allow-list disables the
// default bogon prefixes (so loopback is reachable for tests).
func newGuardWithAllow(t *testing.T, allow []config.TargetRule) *Guard {
	t.Helper()
	cfg := &config.SecurityConfig{
		Targets: config.TargetPolicy{Allow: allow},
		Network: config.NetworkPolicy{
			AllowIPv4:            ptrBool(true),
			AllowIPv6:            ptrBool(false),
			DisableDefaultBogons: true,
			BlockLoopback:        ptrBool(false),
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

// TestGuard_MethodAndPathEnforced verifies that a rule with
// `methods:` and `paths:` allow-lists rejects requests whose method
// or path is outside the list. This is the regression test for
// PLAN §5.2 (per-rule HTTP method/path filter).
func TestGuard_MethodAndPathEnforced(t *testing.T) {
	g := newGuardWithAllow(t, []config.TargetRule{
		{
			Type:    "cidr",
			Pattern: "127.0.0.0/8",
			Tools:   []string{"http_probe"},
			Methods: []string{"GET"},
			Paths:   []string{"/health", "/api/**/status"},
		},
	})

	cases := []struct {
		name    string
		path    string
		method  string
		wantOK  bool
		wantCat DenyCategory
	}{
		{"GET allowed path", "/health", "GET", true, ""},
		{"GET allowed cross-label path", "/api/v1/status", "GET", true, ""},
		{"GET another allowed cross-label", "/api/v2/anything/status", "GET", true, ""},
		{"POST blocked by method", "/health", "POST", false, DenyMethod},
		{"GET path not allowed", "/admin", "GET", false, DenyPath},
		{"lower-case get normalised to GET", "/health", "get", true, ""},
		// An empty Method on the request side does not bypass the
		// rule's method allow-list: the rule explicitly restricts
		// methods, and an empty request value is rejected. (Empty
		// only means "no constraint" when the rule itself omits
		// `methods:` — see TestGuard_MethodsPaths_EmptyMeansAny.)
		{"empty method rejected when rule has methods", "/health", "", false, DenyMethod},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tgt, err := g.Authorize(t.Context(), Request{
				Tool:   "http_probe",
				Scheme: "http",
				Host:   "127.0.0.1",
				Port:   80,
				Path:   tc.path,
				Method: tc.method,
			})
			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected allow, got %v", err)
				}
				tgt.Release()
				return
			}
			if err == nil {
				tgt.Release()
				t.Fatalf("expected denial, got allow")
			}
			var de *DenyError
			if !errors.As(err, &de) {
				t.Fatalf("expected *DenyError, got %T", err)
			}
			if de.Category != tc.wantCat {
				t.Errorf("category = %s, want %s (err=%v)", de.Category, tc.wantCat, err)
			}
		})
	}
}

// TestGuard_MethodsPaths_EmptyMeansAny confirms the documented
// semantics: a rule without `methods:` and without `paths:` accepts
// any method/path (per-user decision: "tout autoriser par défaut").
func TestGuard_MethodsPaths_EmptyMeansAny(t *testing.T) {
	g := newGuardWithAllow(t, []config.TargetRule{
		{
			Type:    "cidr",
			Pattern: "127.0.0.0/8",
			Tools:   []string{"http_probe"},
		},
	})

	for _, c := range []struct{ method, path string }{
		{"GET", "/"},
		{"POST", "/anything/at/all"},
		{"DELETE", "/users/42"},
		{"HEAD", "/v1/status"},
	} {
		tgt, err := g.Authorize(t.Context(), Request{
			Tool:   "http_probe",
			Scheme: "http",
			Host:   "127.0.0.1",
			Port:   80,
			Method: c.method,
			Path:   c.path,
		})
		if err != nil {
			t.Fatalf("method=%q path=%q: %v", c.method, c.path, err)
		}
		tgt.Release()
	}
}
