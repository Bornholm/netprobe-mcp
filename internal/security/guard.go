package security

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/security/errs"
)

type Purpose string

const (
	PurposeProbe     Purpose = "probe"
	PurposeMeta      Purpose = "meta"
	PurposeAIAFetch  Purpose = "aia_fetch"
	PurposeOCSPQuery Purpose = "ocsp_query"
	PurposeICMPProbe Purpose = "icmp_probe"
)

// Request is the input to the Guard pipeline.
type Request struct {
	Tool      string
	SessionID string
	Scheme    string
	Host      string
	Port      uint16
	Path      string
	Method    string
	Purpose   Purpose
}

// SafeTarget is the only addressable identity downstream code may dial.
// Construction is restricted to Guard.Authorize; the unexported field is a
// belt-and-braces invariant that fails compilation if a future caller tries
// to build one from another package.
type SafeTarget struct {
	Hostname    string
	IP          netip.Addr
	AllIPs      []netip.Addr
	Port        uint16
	Scheme      string
	MatchedRule string
	ResolvedAt  time.Time
	DNSTime     time.Duration

	releaseOnce sync.Once
	release     func()
}

func (t *SafeTarget) Release() {
	if t.release == nil {
		return
	}
	t.releaseOnce.Do(t.release)
}

func (t *SafeTarget) Describe() string {
	return fmt.Sprintf("%s://%s:%d (%s)", t.Scheme, t.Hostname, t.Port, t.IP.String())
}

// RateKey is the IP-based identity used by per-target rate limiters. Using
// the hostname instead would let an agent cycle through CNAMEs that share
// the same backing IP.
func (t *SafeTarget) RateKey() string {
	return t.IP.String()
}

// (Limiter and RateKey are re-exported from the errs sub-package via errors.go)

type Guard struct {
	cfg      *config.SecurityConfig
	matcher  *TargetMatcher
	filter   *IPFilter
	resolver *SafeResolver
	dialer   *SafeDialer
	limiter  Limiter
}

func NewGuard(cfg *config.SecurityConfig, resolver *SafeResolver, dialer *SafeDialer, filter *IPFilter, limiter Limiter) (*Guard, error) {
	m, err := NewTargetMatcher(cfg.Targets.Allow, cfg.Targets.Deny)
	if err != nil {
		return nil, fmt.Errorf("compile matchers: %w", err)
	}
	return &Guard{
		cfg:      cfg,
		matcher:  m,
		filter:   filter,
		resolver: resolver,
		dialer:   dialer,
		limiter:  limiter,
	}, nil
}

// Authorize runs the full pipeline and returns a SafeTarget that downstream
// code can use to dial. DenyError is returned for any refusal, with a safe
// public message and an internal cause kept out of the agent's view.
func (g *Guard) Authorize(ctx context.Context, req Request) (*SafeTarget, error) {
	host, err := NormalizeHost(req.Host)
	if err != nil {
		return nil, err
	}

	// IP literal path: no DNS, just match + filter.
	var resolved *ResolveResult
	if addr, perr := netip.ParseAddr(host); perr == nil {
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		if err := g.filter.Check(addr); err != nil {
			return nil, err
		}
		resolved = &ResolveResult{Hostname: host, Addrs: []netip.Addr{addr}}
	} else {
		if err := ValidateIPLiteral(host); err == nil {
			return nil, &DenyError{Category: DenyMalformed, Reason: "unparseable host (non-canonical IP encoding)"}
		}
		resolved, err = g.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
	}

	if len(resolved.Addrs) == 0 {
		return nil, &DenyError{Category: DenyIPRange, Reason: "no permitted address for host"}
	}

	primary := resolved.Addrs[0]

	// Match on the hostname AND the resolved IP (for CIDR rules). This
	// double-check prevents an attacker who controls DNS for an allowed
	// hostname from sneaking out via a cidr allow rule that does not
	// actually contain the hostname.
	mr := g.matcher.Match(host, req.Scheme, req.Port, primary, req.Tool, req.Purpose)
	if !mr.Allowed {
		denied := &DenyError{
			Category: DenyNotAllowed,
			Reason:   fmt.Sprintf("host %q is not in the allow-list", host),
			Hint:     "call probe_policy to list permitted targets",
		}
		if mr.DenyReason != "" {
			denied.Internal = fmt.Errorf("match: %s", mr.DenyReason)
		}
		return nil, denied
	}

	if !mr.Rule.portAllowed(req.Port) {
		return nil, &DenyError{
			Category: DenyPort,
			Reason:   fmt.Sprintf("port %d not permitted by rule", req.Port),
		}
	}
	if !mr.Rule.schemeAllowed(req.Scheme) {
		return nil, &DenyError{
			Category: DenyScheme,
			Reason:   fmt.Sprintf("scheme %q not permitted by rule", req.Scheme),
		}
	}
	if !mr.Rule.toolAllowed(req.Tool) {
		return nil, &DenyError{
			Category: DenyToolTarget,
			Reason:   fmt.Sprintf("tool %q not permitted by rule", req.Tool),
		}
	}
	if !mr.Rule.purposeAllowed(req.Purpose) {
		return nil, &DenyError{
			Category: DenyToolTarget,
			Reason:   fmt.Sprintf("purpose %q not permitted by rule", req.Purpose),
		}
	}

	release, err := g.limiter.Acquire(ctx, errs.RateKey{
		SessionID: req.SessionID,
		Tool:      req.Tool,
		Target:    primary.String(),
	})
	if err != nil {
		var de *errs.DenyError
		if errors.As(err, &de) {
			return nil, de
		}
		return nil, &DenyError{Category: DenyRateLimit, Reason: "rate limit or concurrency cap exceeded"}
	}

	t := &SafeTarget{
		Hostname:    host,
		IP:          primary,
		AllIPs:      append([]netip.Addr(nil), resolved.Addrs...),
		Port:        req.Port,
		Scheme:      req.Scheme,
		MatchedRule: mr.Rule.id,
		ResolvedAt:  time.Now(),
		DNSTime:     resolved.Duration,
		release:     release,
	}
	return t, nil
}

func (g *Guard) Dialer() *SafeDialer     { return g.dialer }
func (g *Guard) Resolver() *SafeResolver { return g.resolver }
func (g *Guard) Filter() *IPFilter       { return g.filter }

// CheckHostname validates a hostname against the IP filter and the
// allow-list matcher without acquiring any rate-limit slot. It is
// intended for callers that must pre-validate a QNAME (DNS probe) or a
// redirect Location (HTTP probe) cheaply, before the real target is
// authorised through Guard.Authorize.
//
// The hostname is normalized and, if it parses as an IP literal, checked
// against the IP filter directly. Hostnames are matched against the
// allow-list using only the textual name (no DNS resolution), so this
// call does not require a working resolver. CIDR allow rules that rely
// on resolved IPs are NOT enforced here; the full Guard.Authorize path
// must still be used for the actual network target.
func (g *Guard) CheckHostname(ctx context.Context, host, tool string) error {
	host, err := NormalizeHost(host)
	if err != nil {
		return err
	}
	if addr, perr := netip.ParseAddr(host); perr == nil {
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		return g.filter.Check(addr)
	}
	// Hostname: do not resolve. The matcher evaluates exact, suffix,
	// glob, and regexp rules against the hostname string. CIDR rules
	// require a resolved IP and are skipped here.
	mr := g.matcher.Match(host, "dns", 0, netip.Addr{}, tool, PurposeProbe)
	if !mr.Allowed {
		denied := &DenyError{
			Category: DenyNotAllowed,
			Reason:   fmt.Sprintf("host %q is not in the allow-list", host),
			Hint:     "call probe_policy to list permitted targets",
		}
		if mr.DenyReason != "" {
			denied.Internal = fmt.Errorf("match: %s", mr.DenyReason)
		}
		return denied
	}
	return nil
}
