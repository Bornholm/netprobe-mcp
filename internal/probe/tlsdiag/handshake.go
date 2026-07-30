package tlsdiag

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// handshakeOutcome captures the raw TLS observation. It is the input to
// chain.go, cert.go and ocsp.go — keeping the raw state out of the
// public Report makes the analyser easier to test.
type handshakeOutcome struct {
	ConnState tls.ConnectionState
	Err       error
	Duration  time.Duration
	NetConn   net.Conn // for diagnostics; nil after Close
}

// mainHandshake performs a single TLS handshake against the authorized
// target. The dialer is pinned to target.IP, so the resolved IP from
// the Guard pipeline is honoured and no rebinding can occur.
//
// The function returns both the outcome and a closer callback. Callers
// MUST invoke closer exactly once.
func (a *Analyzer) mainHandshake(ctx context.Context, target *security.SafeTarget, opts DiagnoseOptions) (*handshakeOutcome, func(), error) {
	start := time.Now()

	handshakeTimeout := a.cfg.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = 10 * time.Second
	}
	hsCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	tlsCfg := a.tlsConfig(target, opts)

	dialFn := a.dialer.PinnedDialContext(target)
	// The dialer wraps a custom Control that validates the IP just
	// before connect(2), giving us belt-and-braces protection.
	rawConn, err := dialFn(hsCtx, "tcp", net.JoinHostPort(target.Hostname, itoa(int(target.Port))))
	if err != nil {
		return nil, func() {}, err
	}

	// Handshake MUST use a timeout-bounded context so that the post-
	// handshake read of ConnectionState cannot stall past the budget.
	tlsConn := tls.Client(rawConn, tlsCfg)
	defer func() {
		_ = tlsConn.Close()
	}()

	hsErr := tlsConn.HandshakeContext(hsCtx)
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 && hsErr == nil {
		// Defensive: a successful handshake with zero peer certs is a
		// bug in the analyser or in the upstream connection. Surface
		// it explicitly rather than silently producing empty reports.
		hsErr = errEmptyPeerCertificates
	}
	outcome := &handshakeOutcome{
		ConnState: state,
		Err:       hsErr,
		Duration:  time.Since(start),
		NetConn:   rawConn,
	}
	closer := func() {
		_ = tlsConn.Close()
	}
	return outcome, closer, nil
}

// errEmptyPeerCertificates is returned when the handshake completed
// without presenting any peer certificates — a programming error in
// either the analyser or the upstream server.
var errEmptyPeerCertificates = fmt.Errorf("tlsdiag: handshake succeeded but no peer certificates were presented")

func (a *Analyzer) tlsConfig(target *security.SafeTarget, opts DiagnoseOptions) *tls.Config {
	sni := opts.ServerName
	if sni == "" {
		sni = target.Hostname
	}
	return &tls.Config{
		ServerName:         sni,
		MinVersion:         a.cfg.MinTLSVersion,
		MaxVersion:         a.cfg.MaxTLSVersion,
		RootCAs:            a.rootPool(),
		InsecureSkipVerify: false, // see insecure_guard_test.go
		// Time is overridden so tests with a fixed clock can verify
		// chains that would otherwise be flagged as expired by the
		// real wall clock. In production, the function is omitted
		// (nil) and Go falls back to time.Now.
		Time: a.now,
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
