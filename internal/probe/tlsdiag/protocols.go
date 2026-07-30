// Active TLS protocol enumeration. Performs up to four additional
// handshakes against the authorized target, each forcing a single
// TLS version (MinVersion = MaxVersion = v). The result is a
// ProtocolSupport that distinguishes "supported" from "not tested".
//
// InsecureSkipVerify=true is REQUIRED here — the goal is to measure
// what the server is willing to negotiate, not whether the
// certificate on offer is valid. The setting is confined to this
// file via TestInsecureSkipVerifyIsConfined.

package tlsdiag

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// probeProtocols opens four handshakes, one per TLS version, against
// the target. The connection is closed as soon as the handshake
// outcome is known; no application data is exchanged.
//
// The function never panics on transport-level errors. It returns a
// ProtocolSupport with the negotiated version recorded as supported /
// not_supported for each probe. SSLv3 is reported as "not_tested"
// because Go's runtime refuses to dial with that version.
func (a *Analyzer) probeProtocols(ctx context.Context, target *security.SafeTarget) ProtocolSupport {
	ps := ProtocolSupport{
		SSLv30: TriUnknown,
		Probed: true,
		Note:   "SSLv3 not testable with Go's crypto/tls client; reported as not_tested",
	}
	probes := []struct {
		v    uint16
		set  *TriState
		name string
	}{
		{tls.VersionTLS10, &ps.TLS10, "TLS 1.0"},
		{tls.VersionTLS11, &ps.TLS11, "TLS 1.1"},
		{tls.VersionTLS12, &ps.TLS12, "TLS 1.2"},
		{tls.VersionTLS13, &ps.TLS13, "TLS 1.3"},
	}

	dialFn := a.dialer.PinnedDialContext(target)
	for _, probe := range probes {
		if ctx.Err() != nil {
			*probe.set = TriUnknown
			continue
		}
		if err := a.probeVersionHandshake(ctx, target, dialFn, probe.v); err == nil {
			*probe.set = TriYes
		} else {
			*probe.set = TriNo
		}
	}
	return ps
}

// probeVersionHandshake opens a single connection, forces the
// requested version, and returns nil if the handshake completed
// successfully (regardless of whether the certificate validated).
//
// The connection is closed as soon as the outcome is known.
func (a *Analyzer) probeVersionHandshake(ctx context.Context, target *security.SafeTarget, dialFn func(context.Context, string, string) (net.Conn, error), version uint16) error {
	hsCtx, cancel := context.WithTimeout(ctx, a.cfg.HandshakeTimeout)
	defer cancel()

	cfg := &tls.Config{
		ServerName: target.Hostname,
		MinVersion: version,
		MaxVersion: version,
		// Justification: we are measuring the server's protocol
		// acceptance, not validating its certificate. The main
		// handshake already does the validation. This setting is
		// permitted only inside this file (see
		// TestInsecureSkipVerifyIsConfined).
		InsecureSkipVerify: true, //nolint:gosec // intentional, justified above
		Time:               a.now,
	}

	rawConn, err := dialFn(hsCtx, "tcp", net.JoinHostPort(target.Hostname, itoa(int(target.Port))))
	if err != nil {
		return err
	}
	defer func() { _ = rawConn.Close() }()

	tlsConn := tls.Client(rawConn, cfg)
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		return err
	}
	return nil
}

// errProtocolProbeInconclusive is reserved for a future refinement
// where a TLS 1.3 client could silently fall back to TLS 1.2 —
// in that case the binary outcome (success / failure) would not
// capture what the server actually negotiated.
var errProtocolProbeInconclusive = errors.New("tlsdiag: protocol probe inconclusive")
