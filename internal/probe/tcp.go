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
	// Dialogue selects a hard-coded, name-only exchange from the
	// catalogue (see tcp_dialogue.go). When set, ReadBanner is
	// ignored: the steps defined by the dialogue own the read
	// budget. Available IDs: smtp_banner, imap_capability,
	// pop3_banner, mysql_handshake. The agent cannot send any
	// byte that the prober does not have a literal for (PLAN
	// §7.3, option a).
	Dialogue DialogueID `json:"dialogue,omitempty" jsonschema:"named dialogue to execute; see tcp_dialogue.go for IDs"`
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

	if opts.Dialogue != "" {
		return p.runDialogue(ctx, target, dialer, opts, start)
	}
	return p.runBanner(ctx, target, dialer, opts, start)
}

// runBanner is the legacy code path (plain TCP connect +
// optional banner read). Kept separate so the dialogue path
// can stay tight and avoid banner-specific dead branches.
func (p *TCPProber) runBanner(ctx context.Context, target *security.SafeTarget, dialer *security.SafeDialer, opts TCPOptions, start time.Time) (*Result, error) {
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

// runDialogue executes the named dialogue against the target.
//
// The prober NEVER composes bytes from the agent. The agent only
// picks an ID from a closed catalogue (tcp_dialogue.go); every
// send literal is hard-coded in source. A failed Expect at any
// step aborts the dialogue and the result is reported with
// Success=false and ErrorClass="protocol", so the agent knows
// the protocol mismatch was a target fault, not a tool fault.
func (p *TCPProber) runDialogue(ctx context.Context, target *security.SafeTarget, dialer *security.SafeDialer, opts TCPOptions, start time.Time) (*Result, error) {
	total := time.Duration(opts.TimeoutMs) * time.Millisecond
	if total <= 0 {
		total = p.dialTimeout
	}
	dlg, err := CompileDialogue(opts.Dialogue, total)
	if err != nil {
		return nil, err
	}

	dctx, cancel := context.WithTimeout(ctx, p.dialTimeout)
	defer cancel()

	dialFn := dialer.PinnedDialContext(target)
	conn, err := dialFn(dctx, "tcp", net.JoinHostPort(target.Hostname, fmt.Sprintf("%d", target.Port)))
	if err != nil {
		return p.errorResult(target, opts, err, time.Since(start)), nil
	}
	defer func() { _ = conn.Close() }()

	res := &Result{
		Success: true,
		Probe:   "tcp_probe",
		Target: Target{
			Requested:  fmt.Sprintf("%s:%d", opts.Host, opts.Port),
			Hostname:   target.Hostname,
			ResolvedIP: target.IP.String(),
			Port:       target.Port,
		},
		TCP: &TCPResult{
			Connected:  true,
			RemoteAddr: conn.RemoteAddr().String(),
			Dialogue:   string(dlg.ID),
		},
	}

	allOK := true
	for i := 0; i < len(dlg.Steps); i++ {
		step := dlg.Steps[i]
		ok, snippet, stepErr := p.executeDialogueStep(ctx, conn, dlg, i, p.maxReadBytes)
		sr := TCPStepResult{
			Label:   step.Label,
			Sent:    string(step.Send),
			Matched: ok,
			Excerpt: snippet,
		}
		res.TCP.Steps = append(res.TCP.Steps, sr)
		if stepErr != nil {
			// Connection error mid-dialogue → mark the
			// whole probe as failed.
			res.Success = false
			res.Error = sanitizeNetErr(stepErr)
			res.ErrorClass = classifyNetError(stepErr)
			allOK = false
			break
		}
		if !ok {
			allOK = false
			// A mismatched Expect is a target fault, not
			// a tool error. Surface as Success=false
			// without IsError (handled in the MCP layer).
			res.Error = fmt.Sprintf("dialogue %q step %d (%s): expect not matched", dlg.ID, i, step.Label)
			res.ErrorClass = "protocol"
			break
		}
	}

	if !allOK {
		res.Success = false
	}
	res.DurationMs = ms(time.Since(start))
	res.Timings.TotalMs = res.DurationMs
	res.Timings.DNSMs = ms(target.DNSTime)
	return res, nil
}

// executeDialogueStep runs ONE step: optionally send the step
// bytes, then read until the regex matches or the per-step
// deadline elapses. The function bounds the read at maxBytes to
// defend against a server that streams indefinitely.
//
// Empty Expect is a special case: the step is "send and don't
// wait for anything in particular" (e.g. a polite LOGOUT). We
// flush the write and return success immediately — without
// attempting to read, which would block until the server times
// out the half-open socket.
func (p *TCPProber) executeDialogueStep(ctx context.Context, conn net.Conn, dlg *CompiledDialogue, i int, maxBytes int64) (bool, string, error) {
	_ = dlg.Steps[i] // referenced only via the helpers below
	sendBytes := dlg.SendBytes(i)
	_ = conn.SetWriteDeadline(time.Now().Add(dlg.StepDeadline(i)))
	if len(sendBytes) > 0 {
		if _, err := conn.Write(sendBytes); err != nil {
			return false, "", err
		}
	}
	// Clear write deadline before reading (the underlying
	// socket inherits it otherwise on some platforms).
	_ = conn.SetWriteDeadline(time.Time{})

	re := dlg.ExpectPattern(i)
	if re == nil {
		// No Expect set: the step was a pure send (LOGOUT,
		// QUIT-with-no-expect, ...). Count it as success
		// without ever reading.
		return true, "", nil
	}

	deadline := time.Now().Add(dlg.StepDeadline(i))
	_ = conn.SetReadDeadline(deadline)

	buf := make([]byte, 4096)
	var acc strings.Builder
	total := int64(0)
	limited := io.LimitReader(conn, maxBytes+1)

	// respect parent context cancellation on top of the socket
	// deadline.
	for {
		select {
		case <-ctx.Done():
			return false, acc.String(), ctx.Err()
		default:
		}
		n, err := limited.Read(buf)
		if n > 0 {
			total += int64(n)
			if acc.Len()+n <= int(maxBytes) {
				acc.Write(buf[:n])
			} else if acc.Len() < int(maxBytes) {
				acc.Write(buf[:int(maxBytes)-acc.Len()])
			}
			if re.MatchString(acc.String()) {
				return true, SanitizeSnippet(acc.String()), nil
			}
		}
		if err != nil {
			// EOF or timeout with no match → step failed.
			return false, SanitizeSnippet(acc.String()), nil
		}
		if total >= maxBytes {
			// Read enough: stop even if we never matched.
			return false, SanitizeSnippet(acc.String()), nil
		}
	}
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
