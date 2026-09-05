package security

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/ratelimit"
)

// A query name is not a host name. RFC 8552 reserves the underscored
// labels — _dmarc, _domainkey, _tcp, _25 — for records an operator asks a
// probe about, and rejecting them as malformed is the difference between
// "I could not look it up" and "you have no DMARC record". The second is a
// wrong answer that sends someone fixing what is not broken.

func TestNormalizeQueryName_AcceptsUnderscoredLabels(t *testing.T) {
	cases := map[string]string{
		"_dmarc.example.com":                    "_dmarc.example.com",
		"selector._domainkey.example.com":       "selector._domainkey.example.com",
		"_sip._tcp.example.com":                 "_sip._tcp.example.com",
		"_25._tcp.mail.example.com":             "_25._tcp.mail.example.com",
		"_DMARC.Example.COM":                    "_dmarc.example.com",
		"_dmarc.example.com.":                   "_dmarc.example.com",
		"  _dmarc.example.com  ":                "_dmarc.example.com",
		"example.com":                           "example.com",
		"s1_2024._domainkey.example.com":        "s1_2024._domainkey.example.com",
		"_acme-challenge.sub.example.com":       "_acme-challenge.sub.example.com",
		"_dmarc.a-very-long-name.example.co.uk": "_dmarc.a-very-long-name.example.co.uk",
	}

	for input, want := range cases {
		got, err := NormalizeQueryName(input)
		if err != nil {
			t.Errorf("NormalizeQueryName(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeQueryName(%q) = %q, want %q", input, got, want)
		}
	}
}

// Everything NormalizeHost refuses for a reason other than the underscore,
// NormalizeQueryName refuses too. The relaxation is one character of
// alphabet, not an open door.
func TestNormalizeQueryName_KeepsEveryOtherRefusal(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"unqualified":     "_dmarc",
		"null byte":       "_dmarc.example.com\x00.evil.com",
		"space inside":    "_dmarc.example .com",
		"newline inside":  "_dmarc.exa\nmple.com",
		"slash":           "_dmarc.example.com/evil",
		"at sign":         "_dmarc@example.com",
		"colon":           "_dmarc.example.com:53",
		"bracket":         "[_dmarc.example.com]",
		"comma":           "_dmarc.example.com,evil.com",
		"leading hyphen":  "-dmarc.example.com",
		"trailing hyphen": "dmarc-.example.com",
		"empty label":     "_dmarc..example.com",
		"non ascii":       "_dmarc.exämple.com",
		"too long":        strings.Repeat("a", 250) + ".example.com",
		"label too long":  strings.Repeat("a", 64) + ".example.com",
		"control char":    "_dmarc.example.com\x7f",
		"backslash":       "_dmarc.example\\.com",
		"question mark":   "_dmarc.example.com?a=1",
	}

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := NormalizeQueryName(input); err == nil {
				t.Errorf("NormalizeQueryName(%q) = %q, want a refusal", input, got)
			}
		})
	}

	// Two cases that look like refusals but are not, and are right not to
	// be — noted here so nobody "fixes" them later.
	//
	//   "_dmarc.example.com\n" is trimmed, like any surrounding
	//   whitespace, exactly as NormalizeHost trims it. A newline INSIDE
	//   the name is still refused, which is the case that matters.
	//
	//   "_.example.com" is a one-character label, no less valid than
	//   "a.example.com". Refusing it would add a rule with no security
	//   value: what stops a name from becoming a tunnel is the length,
	//   label-count and entropy budget, not the shape of a single label.
	for _, ok := range []string{"_dmarc.example.com\n", "_.example.com"} {
		if _, err := NormalizeQueryName(ok); err != nil {
			t.Errorf("NormalizeQueryName(%q) refused it: %v", ok, err)
		}
	}
}

// The underscore must not become a way to name a host. Whatever a query
// name may contain, the dialing path is unchanged.
func TestNormalizeHost_StillRefusesUnderscores(t *testing.T) {
	for _, host := range []string{
		"_dmarc.example.com",
		"selector._domainkey.example.com",
		"under_score.example.com",
	} {
		if got, err := NormalizeHost(host); err == nil {
			t.Errorf("NormalizeHost(%q) = %q, want a refusal: an underscored name is a record to ask about, never a host to connect to", host, got)
		}
	}
}

// The guard-level counterpart: CheckQueryName lets an underscored name
// through the allow-list, CheckHostname does not, and the tool scoping of
// the rule still applies to both.
func TestGuard_CheckQueryName(t *testing.T) {
	g := newQueryNameGuard(t)
	ctx := context.Background()

	t.Run("underscored name clears the allow-list", func(t *testing.T) {
		if err := g.CheckQueryName(ctx, "_dmarc.example.com", "dns_probe"); err != nil {
			t.Fatalf("expected _dmarc.example.com to be allowed, got %v", err)
		}
	})

	t.Run("plain name still clears it", func(t *testing.T) {
		if err := g.CheckQueryName(ctx, "example.com", "dns_probe"); err != nil {
			t.Fatalf("expected example.com to be allowed, got %v", err)
		}
	})

	t.Run("CheckHostname still refuses the same name", func(t *testing.T) {
		err := g.CheckHostname(ctx, "_dmarc.example.com", "dns_probe")
		if err == nil {
			t.Fatal("CheckHostname accepted an underscored name")
		}
		var de *DenyError
		if !errors.As(err, &de) || de.Category != DenyMalformed {
			t.Fatalf("expected a malformed-input denial, got %v", err)
		}
	})

	t.Run("a rule scoped to another tool does not apply", func(t *testing.T) {
		if err := g.CheckQueryName(ctx, "_dmarc.example.com", "http_probe"); err == nil {
			t.Fatal("the suffix rule is scoped to dns_probe and must not cover http_probe")
		}
	})

	t.Run("an unlisted name is still refused", func(t *testing.T) {
		if err := g.CheckQueryName(ctx, "_dmarc.attacker.test", "dns_probe"); err == nil {
			t.Fatal("an unlisted name cleared the allow-list")
		}
	})
}

// An operator running a strict, name-by-name allow-list must be able to
// write the record they want asked about. Before, such a policy failed to
// load at all — "hostname does not match DNS label syntax" on a line that
// is a perfectly ordinary DMARC name.
func TestCompileRule_AcceptsUnderscoredPatterns(t *testing.T) {
	for _, kind := range []string{"exact", "suffix"} {
		allow := []config.TargetRule{{
			Type:    kind,
			Pattern: "_dmarc.example.com",
			Tools:   []string{"dns_probe"},
		}}
		if _, err := NewTargetMatcher(allow, nil); err != nil {
			t.Errorf("a %q rule on an underscored name must compile: %v", kind, err)
		}
	}
}

// newQueryNameGuard builds a guard whose allow-list covers example.com by
// suffix, for dns_probe only.
func newQueryNameGuard(t *testing.T) *Guard {
	t.Helper()

	cfg := &config.SecurityConfig{
		Targets: config.TargetPolicy{
			Allow: []config.TargetRule{{
				Type:    "suffix",
				Pattern: "example.com",
				Tools:   []string{"dns_probe"},
			}},
		},
		Network: config.NetworkPolicy{
			BlockPrivate:     ptrBool(true),
			BlockLoopback:    ptrBool(true),
			BlockLinkLocal:   ptrBool(true),
			BlockMulticast:   ptrBool(true),
			BlockUnspecified: ptrBool(true),
			BlockCloudMeta:   ptrBool(true),
			AllowIPv4:        ptrBool(true),
			AllowIPv6:        ptrBool(false),
		},
	}

	filter, err := NewIPFilter(&cfg.Network)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := NewSafeDialer(cfg.Network, filter, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	mgr := ratelimit.NewManager(ratelimit.ManagerConfig{
		Global:     ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerTarget:  ratelimit.RateLimit{RPS: 1000, Burst: 1000},
		PerSession: ratelimit.RateLimit{RPS: 1000, Burst: 1000},
	})
	g, err := NewGuard(cfg, NewSafeResolver(cfg.DNS, filter), dialer, filter, mgr)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
