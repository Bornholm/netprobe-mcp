package security

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
)

// SafeDialer builds connections whose destination has already been validated
// by the Guard pipeline. The Control callback runs just before connect(2)
// and is the last line of defence: it MUST refuse any IP that is not in the
// IP filter.
type SafeDialer struct {
	base    *net.Dialer
	filter  *IPFilter
	timeout time.Duration
}

func NewSafeDialer(cfg config.NetworkPolicy, filter *IPFilter, timeout time.Duration) (*SafeDialer, error) {
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: -1,
		// Disable Happy Eyeballs (FallbackDelay = -1): dual-stack fallback
		// could connect to an IP we did not validate.
		FallbackDelay: -1,
		Control: func(network, address string, _ syscall.RawConn) error {
			return controlCheck(network, address, filter)
		},
	}
	if cfg.SourceIP != "" {
		ip, err := netip.ParseAddr(cfg.SourceIP)
		if err != nil {
			return nil, fmt.Errorf("invalid source_ip %q: %w", cfg.SourceIP, err)
		}
		d.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, 0))
	}
	return &SafeDialer{base: d, filter: filter, timeout: timeout}, nil
}

func controlCheck(network, address string, filter *IPFilter) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("dial blocked: unparseable address %q", address)
	}
	addr := ap.Addr()
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if err := filter.Check(addr); err != nil {
		return fmt.Errorf("dial blocked by IP filter: %w", err)
	}
	return nil
}

// PinnedDialContext returns a DialContext that ignores the address the caller
// asks for and connects to the pre-validated (host, IP, port) triple instead.
// It refuses to dial anything that does not match.
func (d *SafeDialer) PinnedDialContext(target *SafeTarget) func(context.Context, string, string) (net.Conn, error) {
	pinned := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	expectedHost := target.Hostname
	expectedPort := strconv.Itoa(int(target.Port))
	expectedIP := target.IP

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("dial blocked: malformed address")
		}
		if !stringsEqualFoldASCII(host, expectedHost) || port != expectedPort {
			return nil, fmt.Errorf("dial blocked: unexpected destination (pinned to authorized target)")
		}
		switch {
		case expectedIP.Is4():
			network = "tcp4"
		case expectedIP.Is6():
			network = "tcp6"
		}
		return d.base.DialContext(ctx, network, pinned)
	}
}

func stringsEqualFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
