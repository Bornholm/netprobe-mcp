// Package errs holds the typed DenyError and its categories that flow
// between security, ratelimit and the MCP layer without creating import
// cycles between them.
package errs

import (
	"context"
	"errors"
	"time"
)

type Category string

const (
	NotAllowed  Category = "target_not_allowed"
	Explicit    Category = "target_denied"
	IPRange     Category = "ip_range_restricted"
	IPFamily    Category = "ip_family_disabled"
	Malformed   Category = "malformed_input"
	Port        Category = "port_not_allowed"
	Scheme      Category = "scheme_not_allowed"
	Method      Category = "method_not_allowed"
	Path        Category = "path_not_allowed"
	ToolTarget  Category = "tool_not_allowed_for_target"
	RateLimit   Category = "rate_limited"
	Quota       Category = "session_quota_exhausted"
	Concurrency Category = "too_many_concurrent_probes"
	DNSFailure  Category = "dns_resolution_failed"
	Disabled    Category = "probe_type_disabled"
	Resolver    Category = "resolver_not_allowed"
)

type DenyError struct {
	Category   Category
	Reason     string
	Hint       string
	RetryAfter time.Duration
	Internal   error
}

func (e *DenyError) Error() string { return string(e.Category) + ": " + e.Reason }

func (e *DenyError) Unwrap() error { return e.Internal }

func (e *DenyError) WithInternal(err error) *DenyError {
	cp := *e
	cp.Internal = err
	return &cp
}

func (e *DenyError) WithHint(hint string) *DenyError {
	cp := *e
	cp.Hint = hint
	return &cp
}

func (e *DenyError) WithRetryAfter(d time.Duration) *DenyError {
	cp := *e
	cp.RetryAfter = d
	return &cp
}

// RateKey is the (session, tool, target) tuple used by the rate limiter.
// It lives in this package so that both security and ratelimit can refer
// to it without an import cycle.
type RateKey struct {
	SessionID string
	Tool      string
	Target    string
}

// Limiter is the subset of the rate-limit Manager that the Guard needs.
// Defined here so both packages can compile against it without cycles.
type Limiter interface {
	Acquire(ctx context.Context, key RateKey) (release func(), err error)
	AcquireN(ctx context.Context, key RateKey, weight int) (release func(), err error)
}

// PublicReason returns a sanitized, LLM-safe message.
func PublicReason(err error) string {
	var de *DenyError
	if errors.As(err, &de) {
		if de.Hint != "" {
			return de.Reason + " (" + de.Hint + ")"
		}
		return de.Reason
	}
	return "operation not permitted"
}
