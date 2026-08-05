// Tests for the SNI-vs-default probe (PLAN.md §8.5). The probe
// performs a second handshake without SNI and compares the leaf
// certificate against the canonical one. We exercise three
// scenarios with httptest:
//
//   1. Default cert differs from SNI cert → SNI mismatch detected.
//   2. Default cert equals SNI cert → no mismatch, no finding.
//   3. Server rejects no-SNI connections → no finding, no
//      mismatch (strict SNI is GOOD configuration).

package tlsdiag

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// sniTestServer wraps a TLS listener whose behaviour depends on the
// supplied hook. The default behaviour is to serve the same cert
// regardless of SNI; supplying altForNoSNI=true makes it serve a
// different cert when SNI is empty.
type sniTestServer struct {
	ln          net.Listener
	mainCert    *x509.Certificate
	mainKey     *ecdsa.PrivateKey
	altCert     *x509.Certificate
	altKey      *ecdsa.PrivateKey
	rejectNoSNI bool
}

func startSNITestServer(t *testing.T, altForNoSNI, rejectNoSNI bool) *sniTestServer {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	// Main cert: CN=localhost, SAN=localhost.
	mainKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mainTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	mainDER, err := x509.CreateCertificate(rand.Reader, mainTmpl, rootCert, &mainKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	mainCert, err := x509.ParseCertificate(mainDER)
	if err != nil {
		t.Fatal(err)
	}

	// Alt cert: CN=alternate.localhost, no SAN of localhost.
	altKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	altTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "alternate.localhost"},
		DNSNames:              []string{"alternate.localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	altDER, err := x509.CreateCertificate(rand.Reader, altTmpl, rootCert, &altKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	altCert, err := x509.ParseCertificate(altDER)
	if err != nil {
		t.Fatal(err)
	}

	// Cache the root on the server so tests can extract it.
	rootCertCached = rootCert

	cfg := sniTLSConfig(mainCert, mainKey, altCert, altKey, altForNoSNI, rejectNoSNI)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &sniTestServer{
		ln:          ln,
		mainCert:    mainCert,
		mainKey:     mainKey,
		altCert:     altCert,
		altKey:      altKey,
		rejectNoSNI: rejectNoSNI,
	}
	go srv.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return srv
}

// rootCertCached carries the root between startSNITestServer and
// newSNITestEnv within a single test. It is intentionally a package
// global to keep the test fixture code small; tests must not run in
// parallel for this to remain correct.
var rootCertCached *x509.Certificate

func (s *sniTestServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			tlsConn, ok := c.(*tls.Conn)
			if !ok {
				return
			}
			_ = tlsConn.HandshakeContext(context.Background())
			_ = tlsConn.Close()
		}(conn)
	}
}

func (s *sniTestServer) addr() string {
	return s.ln.Addr().String()
}

// sniTLSConfig builds a tls.Config that switches certificate based on
// the SNI signal. When rejectNoSNI is true the GetConfigForClient
// callback returns an error for connections without SNI.
func sniTLSConfig(mainCert *x509.Certificate, mainKey *ecdsa.PrivateKey, altCert *x509.Certificate, altKey *ecdsa.PrivateKey, altForNoSNI, rejectNoSNI bool) *tls.Config {
	mainTLSCert := tls.Certificate{
		Certificate: [][]byte{mainCert.Raw},
		PrivateKey:  mainKey,
	}
	altTLSCert := tls.Certificate{
		Certificate: [][]byte{altCert.Raw},
		PrivateKey:  altKey,
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{mainTLSCert, altTLSCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		if chi.ServerName == "" {
			if rejectNoSNI {
				return nil, errSNIRejected
			}
			if altForNoSNI {
				return &tls.Config{
					Certificates: []tls.Certificate{altTLSCert},
					MinVersion:   tls.VersionTLS12,
				}, nil
			}
			return nil, nil
		}
		return nil, nil
	}
	return cfg
}

// errSNIRejected is returned by GetConfigForClient when the test
// fixture wants to refuse no-SNI connections.
var errSNIRejected = errSNIRefused{}

type errSNIRefused struct{}

func (errSNIRefused) Error() string {
	return "tlsdiag: server refused no-SNI connection (test fixture)"
}

// sniTestEnv builds an Analyzer pointing at a started test server.
// rootPool is shared so the canonical handshake succeeds.
type sniTestEnv struct {
	analyzer *Analyzer
	target   *security.SafeTarget
	server   *sniTestServer
}

func newSNITestEnv(t *testing.T, altForNoSNI, rejectNoSNI bool) *sniTestEnv {
	t.Helper()
	srv := startSNITestServer(t, altForNoSNI, rejectNoSNI)
	pool := x509.NewCertPool()
	pool.AddCert(rootCertCached)

	dialer := mustDialer(t, pool)

	cfg := Config{
		Enabled:               true,
		TotalBudget:           10 * time.Second,
		HandshakeTimeout:      5 * time.Second,
		MinTLSVersion:         tls.VersionTLS12,
		MaxTLSVersion:         tls.VersionTLS13,
		ExpiringSoonDays:      30,
		ExpiringCriticalDays:  7,
		MaxValidityDays:       398,
		ExcessiveValidityDays: 825,
		MinRSAKeyBits:         2048,
		MinECKeyBits:          256,
		Roots:                 pool,
		Now:                   testNow(),
		Dialer:                dialer,
	}
	a := NewAnalyzer(cfg)

	host, port := splitAddr(srv.addr())
	tgt := &security.SafeTarget{
		Hostname: host,
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	return &sniTestEnv{analyzer: a, target: tgt, server: srv}
}

// sniProbeOnly invokes just the SNI probe and returns the result.
// Useful for testing the probe in isolation.
func (e *sniTestEnv) sniProbeOnly(t *testing.T, withSNILeaf *x509.Certificate, opts DiagnoseOptions) SNIReport {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return e.analyzer.probeSNI(ctx, e.target, withSNILeaf, opts)
}

func TestProbeSNI_NoSNIHandshakeSucceeds_DifferentCert(t *testing.T) {
	env := newSNITestEnv(t, true, false)
	rep := env.sniProbeOnly(t, env.server.mainCert, DiagnoseOptions{})
	if !rep.NoSNIHandshakeSucceeded {
		t.Fatalf("no-SNI handshake should have succeeded: %+v", rep)
	}
	if !rep.SNIMismatch {
		t.Errorf("expected SNIMismatch=true (different cert served), got %+v", rep)
	}
	if rep.NoSNISubject == "" {
		t.Errorf("NoSNISubject should be populated")
	}
	if rep.NoSNIFingerprint == "" {
		t.Errorf("NoSNIFingerprint should be populated")
	}
	if rep.NoSNISubject == env.server.mainCert.Subject.String() {
		t.Errorf("expected a different subject, got the same as SNI cert")
	}
}

func TestProbeSNI_NoSNIHandshakeSucceeds_SameCert(t *testing.T) {
	env := newSNITestEnv(t, false, false) // same cert for both
	rep := env.sniProbeOnly(t, env.server.mainCert, DiagnoseOptions{})
	if !rep.NoSNIHandshakeSucceeded {
		t.Fatalf("no-SNI handshake should have succeeded: %+v", rep)
	}
	if rep.SNIMismatch {
		t.Errorf("expected SNIMismatch=false (same cert served), got %+v", rep)
	}
	if rep.NoSNIFingerprint == "" {
		t.Errorf("NoSNIFingerprint should be populated")
	}
}

func TestProbeSNI_NoSNIRefused_StrictSNI(t *testing.T) {
	env := newSNITestEnv(t, false, true) // reject no-SNI connections
	rep := env.sniProbeOnly(t, env.server.mainCert, DiagnoseOptions{})
	if rep.NoSNIHandshakeSucceeded {
		t.Errorf("no-SNI handshake should have been refused, got success: %+v", rep)
	}
	if rep.SNIMismatch {
		t.Errorf("expected SNIMismatch=false when no-SNI failed, got true")
	}
	if rep.NoSNIError == "" {
		t.Errorf("expected a NoSNIError, got empty")
	}
}

func TestProbeSNI_NilLeaf_NoteSet(t *testing.T) {
	env := newSNITestEnv(t, true, false)
	rep := env.sniProbeOnly(t, nil, DiagnoseOptions{})
	if !rep.NoSNIHandshakeSucceeded {
		t.Fatalf("no-SNI handshake should have succeeded: %+v", rep)
	}
	if rep.SNIMismatch {
		t.Errorf("expected SNIMismatch=false when comparison leaf is nil")
	}
	if rep.Note == "" {
		t.Errorf("expected Note explaining no comparison leaf")
	}
}

// TestRuleSNIDefaultMismatch_Triggered exercises the rule itself
// against a synthetic EvalContext. The probe path is covered above.
func TestRuleSNIDefaultMismatch_Triggered(t *testing.T) {
	main := &x509.Certificate{Subject: pkix.Name{CommonName: "main.local"}}
	ec := &EvalContext{
		Leaf:     main,
		Hostname: "main.local",
		SNI: &SNIReport{
			NoSNIHandshakeSucceeded: true,
			NoSNISubject:            "alt.local",
			NoSNIFingerprint:        "deadbeef",
			SNIMismatch:             true,
		},
	}
	findings := newRuleSNIDefaultMismatch().Evaluate(ec)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].ID != "TLS_SNI_DEFAULT_CERT_MISMATCH" {
		t.Errorf("ID = %q, want TLS_SNI_DEFAULT_CERT_MISMATCH", findings[0].ID)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("severity = %s, want high (different subjects)", findings[0].Severity)
	}
}

func TestRuleSNIDefaultMismatch_NoFinding_StrictSNI(t *testing.T) {
	ec := &EvalContext{
		Leaf:     &x509.Certificate{Subject: pkix.Name{CommonName: "main.local"}},
		Hostname: "main.local",
		SNI: &SNIReport{
			NoSNIHandshakeSucceeded: false,
			NoSNIError:              "tls: no SNI extension in ClientHello",
		},
	}
	got := newRuleSNIDefaultMismatch().Evaluate(ec)
	if len(got) != 0 {
		t.Errorf("strict SNI should NOT produce a finding, got %+v", got)
	}
}

func TestRuleSNIDefaultMismatch_NoFinding_SameCert(t *testing.T) {
	main := &x509.Certificate{Subject: pkix.Name{CommonName: "main.local"}}
	ec := &EvalContext{
		Leaf:     main,
		Hostname: "main.local",
		SNI: &SNIReport{
			NoSNIHandshakeSucceeded: true,
			NoSNISubject:            "main.local",
			NoSNIFingerprint:        "same",
		},
	}
	got := newRuleSNIDefaultMismatch().Evaluate(ec)
	if len(got) != 0 {
		t.Errorf("same-cert default should NOT produce a finding, got %+v", got)
	}
}

func TestRuleSNIDefaultMismatch_NoFinding_NilSNI(t *testing.T) {
	ec := &EvalContext{
		Leaf:     &x509.Certificate{Subject: pkix.Name{CommonName: "main.local"}},
		Hostname: "main.local",
		SNI:      nil, // phase was not run
	}
	got := newRuleSNIDefaultMismatch().Evaluate(ec)
	if len(got) != 0 {
		t.Errorf("nil SNI should NOT produce a finding, got %+v", got)
	}
}
