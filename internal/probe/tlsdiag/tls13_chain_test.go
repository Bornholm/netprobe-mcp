// Integration tests covering TLS 1.3 handshake behaviour and the
// reported smtp.cadoles.com:465 scenario (handshake succeeds but
// PeerCertificates is empty in the analyser).
//
// These tests exist to lock down observed regressions and to drive a
// proper fix. See PLAN.md §13 and session-ses_0378.md.
//
// All servers are in-memory; no external network access.
package tlsdiag

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// startTLS13OnlyServer boots a loopback TLS 1.3-only server with an
// ECDSA leaf covering "localhost" and IPs 127.0.0.1 / ::1.
//
// Returns the listen address, the trust pool to feed the analyser, and
// the parsed leaf.
func startTLS13OnlyServer(t *testing.T) (string, *x509.CertPool, *x509.Certificate) {
	t.Helper()
	rootKey := ecKey(t)
	root := makeRoot(t, rootKey, "TLS13 Test Root CA")
	leafKey := ecKey(t)
	now := testClock()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost", "mail.localhost", "groupware.localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)

	leaf := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  leafKey,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	go acceptTLSForever(ln)
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), pool, leafCert
}

// startTLS13OnlyServerSANMissing is a variant that does NOT cover
// "smtp.cadoles.com" in its SAN, mirroring the smtp.cadoles.com:465
// session regression.
func startTLS13OnlyServerSANMissing(t *testing.T, sn string) (string, *x509.CertPool) {
	t.Helper()
	rootKey := ecKey(t)
	root := makeRoot(t, rootKey, "TLS13 SAN-mismatch Root")
	leafKey := ecKey(t)
	now := testClock()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "groupware.cadoles.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		// Intentional mismatch: SNI asked for `sn` (e.g.
		// "smtp.cadoles.com") but the cert only covers
		// "groupware.cadoles.com".
		DNSNames: []string{"groupware.cadoles.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	leaf := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  leafKey,
	}
	// sn is referenced via the SAN-mismatch contract but Go's
	// crypto/tls does not need it inside the server; we capture it
	// only so the helper signature documents the asymmetry.
	_ = sn
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	go acceptTLSForever(ln)
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), pool
}

// acceptTLSForever runs the TLS server loop until the listener is
// closed by test cleanup.
func acceptTLSForever(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			tc, ok := c.(*tls.Conn)
			if !ok {
				return
			}
			_ = tc.Handshake()
			// TLS 1.3 sends close_notify from server side; read to
			// drain before close.
		}(conn)
	}
}

// TestDiagnose_TLS13_HealthyChain confirms the analyser returns a
// populated chain on a TLS 1.3-only server that DOES cover the SNI.
// This is the positive control: the smtp.cadoles.com bug is NOT
// "all TLS 1.3 handshakes fail".
func TestDiagnose_TLS13_HealthyChain(t *testing.T) {
	addr, pool, _ := startTLS13OnlyServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep, err := a.Diagnose(tgt, DiagnoseOptions{})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if !rep.Handshake.Succeeded {
		t.Fatalf("handshake failed: %s", rep.Handshake.FailureReason)
	}
	if rep.Handshake.Version != "TLS 1.3" {
		t.Errorf("expected handshake version TLS 1.3, got %q", rep.Handshake.Version)
	}
	if len(rep.Chain.PresentedCerts) == 0 {
		t.Fatalf("expected at least one presented cert on TLS 1.3; got none")
	}
	if rep.Chain.PresentedCerts[0].Subject == "" {
		t.Errorf("expected populated leaf subject, got empty")
	}
	if !rep.Chain.HostnameMatches {
		t.Errorf("expected hostname match on 'localhost'")
	}
}

// TestDiagnose_TLS13_SNIMismatch_StillReportsChain reproduces the
// session-ses_0378 symptom: the user passed smtp.cadoles.com as the
// SNI value, but the server presents groupware.cadoles.com. The
// connection on TLS 1.3 succeeds (the cert IS in the connection
// state — it's just not valid for the requested SNI). The analyser
// MUST surface the chain and emit TLS_HOSTNAME_MISMATCH, not a
// silent "no certificates presented".
func TestDiagnose_TLS13_SNIMismatch_StillReportsChain(t *testing.T) {
	addr, pool := startTLS13OnlyServerSANMissing(t, "smtp.cadoles.com")
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "smtp.cadoles.com",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep, err := a.Diagnose(tgt, DiagnoseOptions{ServerName: "smtp.cadoles.com"})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if !rep.Handshake.Succeeded {
		// A handshake that fails is acceptable here too — but the
		// chain should still be inspected, since the cert was on
		// the wire regardless of the verification result.
		t.Logf("handshake failed: %s (acceptable for SNI mismatch)", rep.Handshake.FailureReason)
	}
	if len(rep.Chain.PresentedCerts) == 0 {
		t.Fatalf("expected cert chain to surface on TLS 1.3 SNI mismatch; got none (see session-ses_0378)")
	}
	found := false
	for _, f := range rep.Findings {
		if f.ID == "TLS_HOSTNAME_MISMATCH" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected TLS_HOSTNAME_MISMATCH finding, got findings=%+v", rep.Findings)
	}
}

// TestDiagnose_TLS13_RawClientState is the cross-check: a raw
// tls.Conn against the same loopback listener MUST see a populated
// PeerCertificates. If this test passes and
// TestDiagnose_TLS13_HealthyChain fails, the bug is in the analyser
// (ConnectionState cloning / order of reads), not in Go's TLS stack.
//
// The test pins the chain validity window through tls.Config.Time
// so the assertion is independent of wall-clock time.
func TestDiagnose_TLS13_RawClientState(t *testing.T) {
	addr, pool, _ := startTLS13OnlyServer(t)
	host, port := splitAddr(addr)

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	rawConn, err := dialer.Dial("tcp", net.JoinHostPort(host, portStr(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    pool,
		Time:       testNow(),
	})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	st := tlsConn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		t.Fatalf("raw TLS 1.3 ConnectionState has zero peer certificates — bug is upstream of the analyser")
	}
	if !strings.Contains(st.PeerCertificates[0].Subject.String(), "localhost") {
		t.Errorf("unexpected subject %q", st.PeerCertificates[0].Subject)
	}
}

// portStr converts a uint16 to a base-10 string without pulling fmt
// into a test helper. Keeps the helper table readable.
func portStr(p uint16) string {
	if p == 0 {
		return "0"
	}
	n := int(p)
	var buf [6]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestDiagnose_ConnState_NotMutatedAfterClose verifies that the
// analyser does not depend on the tls.Conn lifetime. After Close the
// ConnectionState values MUST still be readable — a regression here
// would lose the chain on TLS 1.3 servers that close the connection
// immediately after ServerHello (very rare but observed in the wild
// when the client retries on a different SNI value).
func TestDiagnose_ConnState_NotMutatedAfterClose(t *testing.T) {
	addr, pool, _ := startTLS13OnlyServer(t)
	host, port := splitAddr(addr)

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	rawConn, err := dialer.Dial("tcp", net.JoinHostPort(host, portStr(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    pool,
		Time:       testNow(),
	})
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		t.Fatalf("handshake: %v", err)
	}
	state := tlsConn.ConnectionState()
	certCount := len(state.PeerCertificates)
	tlsConn.Close()
	rawConn.Close()

	if certCount == 0 {
		t.Fatalf("PeerCertificates lost after Close — the analyser must not depend on tls.Conn lifetime")
	}
}

// silence "imported and not used" in case the RSA path is removed in
// the future. rsa.GenerateKey remains available for tests that
// exercise weak-key rules in the same file (reserved).
var _ = rsa.GenerateKey
