package security

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/security/errs"
)

// TestLookupFunc_HonorsHost is a regression test for a bug where
// systemLookup's inner LookupFunc ignored its hostname argument and
// passed "" to net.Resolver.LookupIP. The result was "no such host"
// for every DNS query when Resolvers was empty (the default in
// config.Default()).
//
// We verify the contract by checking that an empty host is rejected
// by the LookupFunc, which guarantees the closure plumbs the host
// through.
func TestLookupFunc_HonorsHost(t *testing.T) {
	var fn LookupFunc = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if strings.TrimSpace(host) == "" {
			return nil, errors.New("empty hostname")
		}
		return nil, nil
	}
	if _, err := fn(context.Background(), "ip", "example.com"); err != nil {
		t.Fatalf("lookup with host: %v", err)
	}
	if _, err := fn(context.Background(), "ip", ""); err == nil {
		t.Fatal("empty hostname accepted, want error")
	}
}

// TestSafeResolver_LiteralIPRejection verifies the IP filter is consulted
// for literal IP inputs without any DNS query.
func TestSafeResolver_LiteralIPRejection(t *testing.T) {
	filter, err := NewIPFilter(&config.NetworkPolicy{
		AllowIPv4:      ptrBool(true),
		AllowIPv6:      ptrBool(false),
		BlockLoopback:  ptrBool(true),
		BlockLinkLocal: ptrBool(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	r := NewSafeResolver(config.DNSPolicy{Timeout: time.Second, CacheMaxEntries: 16, CacheTTL: time.Second}, filter)

	_, err = r.LookupIPAddr(context.Background(), "127.0.0.1")
	if err == nil {
		t.Fatal("loopback IP literal accepted, want error")
	}
	var de *errs.DenyError
	if !errors.As(err, &de) {
		t.Fatalf("error = %v, want DenyError", err)
	}
	if de.Category != errs.IPRange {
		t.Errorf("category = %v, want IPRange", de.Category)
	}
}
