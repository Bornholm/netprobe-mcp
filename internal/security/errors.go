// Package security re-exports the typed DenyError so existing imports of
// "internal/security" keep working. The actual type lives in the errs
// sub-package to avoid import cycles with ratelimit.
package security

import (
	"errors"

	"github.com/bornholm/netprobe-mcp/internal/security/errs"
)

// DenyError is an alias for the structured refusal type.
type DenyError = errs.DenyError

// DenyCategory mirrors errs.Category under the historical name.
type DenyCategory = errs.Category

// Deny categories (re-exported under the old names).
const (
	DenyNotAllowed  = errs.NotAllowed
	DenyExplicit    = errs.Explicit
	DenyIPRange     = errs.IPRange
	DenyIPFamily    = errs.IPFamily
	DenyMalformed   = errs.Malformed
	DenyPort        = errs.Port
	DenyScheme      = errs.Scheme
	DenyMethod      = errs.Method
	DenyToolTarget  = errs.ToolTarget
	DenyRateLimit   = errs.RateLimit
	DenyQuota       = errs.Quota
	DenyConcurrency = errs.Concurrency
	DenyDNSFailure  = errs.DNSFailure
	DenyDisabled    = errs.Disabled
	DenyResolver    = errs.Resolver
)

// PublicReason is re-exported so callers using security.PublicReason keep working.
func PublicReason(err error) string { return errs.PublicReason(err) }

// RateKey re-exports errs.RateKey for callers within this package tree.
type RateKey = errs.RateKey

// Limiter re-exports errs.Limiter so security.NewGuard accepts the
// ratelimit.Manager (which implements errs.Limiter) without leaking the
// sub-package name to upper layers.
type Limiter = errs.Limiter

// asDeny returns a DenyError found anywhere in err's chain, or nil.
func asDeny(err error) *errs.DenyError {
	var de *errs.DenyError
	if errors.As(err, &de) {
		return de
	}
	return nil
}
