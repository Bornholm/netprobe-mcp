package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// TCPOptions are the agent-facing parameters of tcp_probe.
type TCPOptions struct {
	Host       string `json:"host" jsonschema:"hostname or IP literal to connect to"`
	Port       int    `json:"port" jsonschema:"TCP port (1-65535)"`
	TimeoutMs  int    `json:"timeout_ms,omitempty" jsonschema:"per-request timeout in milliseconds"`
	ReadBanner bool   `json:"read_banner,omitempty" jsonschema:"read and return a sanitized banner"`
}

type TCPProber struct {
	maxReadBytes int64
	dialTimeout  time.Duration
}

func NewTCPProber(maxReadBytes int64, dialTimeout time.Duration) *TCPProber {
	if maxReadBytes <= 0 {
		maxReadBytes = 4096
	}
	return &TCPProber{maxReadBytes: maxReadBytes, dialTimeout: dialTimeout}
}

// Run performs a single TCP connection attempt. The destination has already
// been authorized via the Guard pipeline; this function never re-resolves
// the hostname.
func (p *TCPProber) Run(ctx context.Context, target *security.SafeTarget, dialer *security.SafeDialer, opts TCPOptions) (*Result, error) {
	start := Now()

	if opts.Port <= 0 || opts.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d", opts.Port)
	}
	if target.Port != uint16(opts.Port) {
		return nil, fmt.Errorf("port mismatch: target pinned to %d, options say %d", target.Port, opts.Port)
	}

	dctx, cancel := context.WithTimeout(ctx, p.dialTimeout)
	defer cancel()

	dialFn := dialer.PinnedDialContext(target)
	conn, err := dialFn(dctx, "tcp", net.JoinHostPort(target.Hostname, fmt.Sprintf("%d", target.Port)))
	if err != nil {
		return p.errorResult(target, opts, err, time.Since(start)), nil
	}

	res := &Result{
		Success: true,
		Probe:   "tcp_probe",
		Target: Target{
			Requested:  fmt.Sprintf("%s:%d", opts.Host, opts.Port),
			Hostname:   target.Hostname,
			ResolvedIP: target.IP.String(),
			Port:       target.Port,
		},
		TCP: &TCPResult{Connected: true, RemoteAddr: conn.RemoteAddr().String()},
	}

	if opts.ReadBanner {
		banner, bannerBytes, truncated, rerr := readBanner(ctx, conn, p.maxReadBytes)
		if rerr != nil && !errors.Is(rerr, io.EOF) && !isTimeout(rerr) {
			conn.Close()
			res.Success = false
			res.Error = sanitizeNetErr(rerr)
			res.ErrorClass = classifyNetError(rerr)
			res.DurationMs = ms(time.Since(start))
			res.Timings.TotalMs = res.DurationMs
			return res, nil
		}
		res.TCP.Banner = SanitizeSnippet(banner)
		res.TCP.BannerBytes = bannerBytes
		res.TCP.BannerTruncated = truncated
	}

	_ = conn.Close()
	res.DurationMs = ms(time.Since(start))
	res.Timings.TotalMs = res.DurationMs
	res.Timings.DNSMs = ms(target.DNSTime)
	return res, nil
}

func readBanner(ctx context.Context, conn net.Conn, maxBytes int64) (string, int64, bool, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Second)
	}
	_ = conn.SetReadDeadline(deadline)

	limited := io.LimitReader(conn, maxBytes+1)
	buf := make([]byte, 4096)
	var total int64
	var out strings.Builder
	for {
		n, err := limited.Read(buf)
		if n > 0 {
			total += int64(n)
			if out.Len()+n <= int(maxBytes) {
				out.Write(buf[:n])
			} else if out.Len() < int(maxBytes) {
				out.Write(buf[:int(maxBytes)-out.Len()])
			}
		}
		if err != nil {
			return out.String(), min(total, maxBytes), total > maxBytes, err
		}
		if n == 0 {
			// Defensive: Read returning (0, nil) is rare but possible on
			// some platforms. Treat as EOF to avoid an infinite loop.
			return out.String(), min(total, maxBytes), total > maxBytes, io.EOF
		}
		if total >= maxBytes {
			return out.String(), maxBytes, true, nil
		}
	}
}

func (p *TCPProber) errorResult(target *security.SafeTarget, opts TCPOptions, err error, dur time.Duration) *Result {
	r := &Result{
		Success:    false,
		Probe:      "tcp_probe",
		Target:     targetDescribe(target, opts),
		Error:      sanitizeNetErr(err),
		ErrorClass: classifyNetError(err),
	}
	r.DurationMs = ms(dur)
	r.Timings.TotalMs = r.DurationMs
	r.Timings.DNSMs = ms(target.DNSTime)
	return r
}

func targetDescribe(target *security.SafeTarget, opts TCPOptions) Target {
	t := Target{
		Requested:  fmt.Sprintf("%s:%d", opts.Host, opts.Port),
		Hostname:   target.Hostname,
		ResolvedIP: target.IP.String(),
		Port:       target.Port,
	}
	return t
}

// SanitizeNetErr trims a network error to a safe length for agent output.
func SanitizeNetErr(err error) string { return sanitizeNetErr(err) }

func sanitizeNetErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func classifyNetError(err error) string {
	if err == nil {
		return ""
	}
	if isTimeout(err) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return "network"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"):
		return "connect_refused"
	case strings.Contains(s, "no route to host"):
		return "unreachable"
	case strings.Contains(s, "permission denied"):
		return "permission_denied"
	case strings.Contains(s, "dial blocked"):
		return "policy"
	}
	return "network"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
