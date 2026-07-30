package security

import (
	"net/netip"
	"strings"
	"testing"
	"unicode"
)

// FuzzNormalizeHost asserts three invariants of the host normalizer:
//  1. Normalize is idempotent.
//  2. A normalized IP literal is never in the deny-list.
//  3. No control characters survive normalization.
func FuzzNormalizeHost(f *testing.F) {
	f.Add("example.com")
	f.Add("127.0.0.1")
	f.Add("::ffff:127.0.0.1")
	f.Add("example.com\x00.evil.com")
	f.Add("0177.0.0.1")

	f.Fuzz(func(t *testing.T, host string) {
		norm, err := NormalizeHost(host)
		if err != nil {
			return
		}
		again, err2 := NormalizeHost(norm)
		if err2 != nil || again != norm {
			t.Fatalf("not idempotent: %q -> %q -> (%q, %v)", host, norm, again, err2)
		}
		if addr, perr := netip.ParseAddr(norm); perr == nil {
			f := &IPFilter{}
			if ferr := f.Check(addr); ferr == nil {
				t.Fatalf("normalized IP %v from %q should be blocked", addr, host)
			}
		}
		if strings.ContainsFunc(norm, unicode.IsControl) {
			t.Fatalf("control characters survived normalization: %q", norm)
		}
	})
}
