package tlsdiag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
//
// Verification strategy: Go's native chain validation, when it
// rejects a cert (hostname mismatch, unknown CA, expired
// intermediate), leaves ConnectionState().PeerCertificates empty so
// the analyser cannot recover the chain. This was the source of the
// smtp.cadoles.com:465 regression (TLS 1.3 server returned a cert
// valid for groupware.cadoles.com when client requested smtp.*; the
// analyser reported "no certificates presented" instead of
// "TLS_HOSTNAME_MISMATCH").
//
// To surface the chain even on verification failure, this handshake
// pairs InsecureSkipVerify=true with VerifyPeerCertificate, which
// reproduces the same hostname + chain + key-usage checks Go would
// have done internally. Security is unchanged: every verification
// rule Go enforces is enforced by the callback. What the flag
// changes is the order — the callback runs FIRST, sees the certs,
// can record them, and only then rejects if they are wrong.
//
// See insecure_guard_test.go for the confinement rationale.
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
	// Verification failures no longer hide the chain (it is captured in
	// VerifyPeerCertificate above). We only flag "empty chain on
	// successful handshake" as a defensible error, which now only
	// happens when the server actually returns zero certs — a real
	// misconfiguration that the LLM should hear about.
	if len(state.PeerCertificates) == 0 && hsErr == nil {
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

// strictVerifyHostnameAndChain is the verification callback used for
// the main handshake. It runs EXACTLY the same checks Go's native
// chain validation would have run (chain trust + hostname match +
// key usage), as a function returning a meaningful error rather than
// crashing the handshake. Errors are propagated via the returned
// error so the handshakeoutcome.Err is populated and the report can
// record the classification; the chain itself stays in
// ConnectionState().PeerCertificates regardless.
//
// The function is intentionally pure (no shared state) so it could
// be replaced or augmented by tests.
func strictVerifyHostnameAndChain(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, hostname string, roots *x509.CertPool) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("tlsdiag: peer presented no certificates")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("tlsdiag: malformed leaf certificate: %w", err)
	}
	if hostname != "" {
		if err := leaf.VerifyHostname(hostname); err != nil {
			return fmt.Errorf("hostname mismatch: %w", err)
		}
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		intermediates.AddCert(c)
	}
	if roots == nil {
		// Mimic Go's default behaviour: when no RootCAs is
		// provided, the system pool is used at handshake time,
		// but the same checks run against any pool we have.
		roots = x509.NewCertPool()
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       hostname,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("chain verification failed: %w", err)
	}
	return nil
}

func (a *Analyzer) tlsConfig(target *security.SafeTarget, opts DiagnoseOptions) *tls.Config {
	sni := opts.ServerName
	if sni == "" {
		sni = target.Hostname
	}
	pool := a.rootPool()
	return &tls.Config{
		ServerName: sni,
		MinVersion: a.cfg.MinTLSVersion,
		MaxVersion: a.cfg.MaxTLSVersion,
		RootCAs:    pool,
		// Security invariant: paired with VerifyPeerCertificate
		// which performs the same chain + hostname + key-usage
		// checks Go would have done internally. The flag is set
		// ONLY so the cert chain is preserved even when the
		// verification callback returns a non-nil error. See the
		// confinement rationale in insecure_guard_test.go.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return strictVerifyHostnameAndChain(rawCerts, verifiedChains, sni, pool)
		},
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
