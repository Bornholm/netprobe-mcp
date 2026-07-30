package probe

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// testSafeTarget constructs a SafeTarget for unit tests without going
// through the Guard pipeline. The release function is a no-op, but Go
// won't let us set the unexported field directly. We use a tiny package-
// internal helper in the security package that sets it for us.
func testSafeTarget(addr, scheme string) *security.SafeTarget {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	ip := netip.MustParseAddr(host)
	st := &security.SafeTarget{
		Hostname: host,
		IP:       ip,
		Port:     port,
		Scheme:   scheme,
	}
	security.SetReleaseForTest(st, func() {})
	return st
}
