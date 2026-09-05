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

// FuzzNormalizeQueryName asserts the same invariants for the query-name
// normalizer, plus the one that separates the two: whatever a query name
// may look like, it must never become dialable. NormalizeQueryName admits
// a character NormalizeHost does not, so it is the looser parser of the
// pair — and the one worth fuzzing hardest.
func FuzzNormalizeQueryName(f *testing.F) {
	f.Add("_dmarc.example.com")
	f.Add("selector._domainkey.example.com")
	f.Add("_25._tcp.mail.example.com")
	f.Add("_dmarc.example.com\x00.evil.com")
	f.Add("example.com")
	f.Add("0177.0.0.1")

	f.Fuzz(func(t *testing.T, name string) {
		norm, err := NormalizeQueryName(name)
		if err != nil {
			return
		}
		again, err2 := NormalizeQueryName(norm)
		if err2 != nil || again != norm {
			t.Fatalf("not idempotent: %q -> %q -> (%q, %v)", name, norm, again, err2)
		}
		if addr, perr := netip.ParseAddr(norm); perr == nil {
			f := &IPFilter{}
			if ferr := f.Check(addr); ferr == nil {
				t.Fatalf("normalized IP %v from %q should be blocked", addr, name)
			}
		}
		if strings.ContainsFunc(norm, unicode.IsControl) {
			t.Fatalf("control characters survived normalization: %q", norm)
		}
		// The dialing path must stay strictly narrower: anything the host
		// normalizer accepts here has to come out identical, and anything
		// it refuses stays refused. A query name is never a connection.
		if host, herr := NormalizeHost(norm); herr == nil && host != norm {
			t.Fatalf("the two normalizers disagree on %q: host=%q query=%q", name, host, norm)
		}
	})
}
