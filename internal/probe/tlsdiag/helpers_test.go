package tlsdiag

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/security"
)

// testClock returns a fixed time so certificate validity is
// deterministic. The default "now" for tests is 2025-06-01 UTC.
func testClock() time.Time {
	return time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
}

// testNow indirection.
func testNow() func() time.Time {
	now := testClock()
	return func() time.Time { return now }
}

// keyPair returns a freshly generated ECDSA key (the same key can be
// re-used across multiple certs in a chain).
func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec key: %v", err)
	}
	return k
}

// rsaKey returns a freshly generated RSA key with the given bit size.
func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa key (%d): %v", bits, err)
	}
	return k
}

// makeLeaf returns a self-contained leaf certificate template. The
// caller passes a function that mutates the template before signing.
func makeLeaf(t *testing.T, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, mut func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	now := testClock()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"leaf.example.com"},
	}
	if mut != nil {
		mut(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}

// makeIntermediate returns an intermediate CA certificate signed by
// the given parent.
func makeIntermediate(t *testing.T, key, parentKey *ecdsa.PrivateKey, parent *x509.Certificate, cn string) *x509.Certificate {
	t.Helper()
	now := testClock()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}
	return cert
}

// makeRoot returns a self-signed root CA certificate.
func makeRoot(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	now := testClock()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	return cert
}

// buildChain builds a leaf → intermediate → root chain. The caller
// may pass a mutator to alter the leaf template.
func buildChain(t *testing.T, leafMut func(*x509.Certificate)) (*x509.Certificate, *x509.Certificate, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	leaf, inter, root, pool, _, _, _ := buildChainFull(t, leafMut)
	return leaf, inter, root, pool
}

// buildChainFull builds a leaf → intermediate → root chain and also
// returns the underlying ECDSA keys. Used by tests that need to
// forge signatures on the intermediate (e.g. OCSP responder certs).
func buildChainFull(t *testing.T, leafMut func(*x509.Certificate)) (leaf, inter, root *x509.Certificate, pool *x509.CertPool, leafKey, interKey, rootKey *ecdsa.PrivateKey) {
	t.Helper()
	rootKey = ecKey(t)
	root = makeRoot(t, rootKey, "Test Root CA")
	interKey = ecKey(t)
	inter = makeIntermediate(t, interKey, rootKey, root, "Test Intermediate CA")
	leafKey = ecKey(t)
	leaf = makeLeaf(t, leafKey, inter, interKey, leafMut)

	pool = x509.NewCertPool()
	pool.AddCert(root)
	return leaf, inter, root, pool, leafKey, interKey, rootKey
}

// buildChainWithRSA builds a leaf signed with RSA at the given bit
// size. Used by RSA-key rules.
func buildChainWithRSA(t *testing.T, bits int, leafMut func(*x509.Certificate)) (*x509.Certificate, *x509.Certificate, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	rootKey := ecKey(t)
	root := makeRoot(t, rootKey, "Test Root CA")
	interKey := ecKey(t)
	inter := makeIntermediate(t, interKey, rootKey, root, "Test Intermediate CA")
	leafKey := rsaKey(t, bits)
	now := testClock()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"leaf.example.com"},
	}
	if leafMut != nil {
		leafMut(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("create rsa leaf: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse rsa leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return parsed, inter, root, pool
}

// buildChainWithP224 builds a leaf signed with ECDSA on the
// NIST P-224 curve. Used by the weak-curve rule.
func buildChainWithP224(t *testing.T, leafMut func(*x509.Certificate)) (*x509.Certificate, *x509.Certificate, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	rootKey := ecKey(t)
	root := makeRoot(t, rootKey, "Test Root CA")
	interKey := ecKey(t)
	inter := makeIntermediate(t, interKey, rootKey, root, "Test Intermediate CA")
	leafKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("p224 key: %v", err)
	}
	now := testClock()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"leaf.example.com"},
	}
	if leafMut != nil {
		leafMut(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("create p224 leaf: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse p224 leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return parsed, inter, root, pool
}

// safeTargetStub builds a minimal SafeTarget for tests that exercise
// non-dialing helpers.
func safeTargetStub(host string) *security.SafeTarget {
	return &security.SafeTarget{
		Hostname: host,
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     443,
		Scheme:   "tls",
	}
}

// analyzerStub builds an Analyzer with sensible defaults for tests.
func analyzerStub(pool *x509.CertPool) *Analyzer {
	cfg := Config{
		Enabled:               true,
		TotalBudget:           5 * time.Second,
		HandshakeTimeout:      2 * time.Second,
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
	}
	return NewAnalyzer(cfg)
}

// startTLSServer starts an in-memory TLS server using a freshly
// generated self-signed cert. Returns the listen address, the CA pool
// to use for client verification and the leaf certificate. Each call
// regenerates the cert (and matching pool), so tests under -count=N
// get a fresh matching pair.
func startTLSServer(t *testing.T) (string, *x509.CertPool, *x509.Certificate) {
	t.Helper()
	rootKey := ecKey(t)
	root := makeRoot(t, rootKey, "Test Root CA")
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
		DNSNames:              []string{"localhost"},
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

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  leafKey,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
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
				<-done
			}(conn)
		}
	}()
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
	})
	return ln.Addr().String(), pool, leafCert
}

// mustStapleExtension returns a *x509.Certificate template mutation
// that adds the TLS Feature must-staple extension.
func mustStapleExtension(t *testing.T) func(*x509.Certificate) {
	return func(tmpl *x509.Certificate) {
		t.Helper()
		// SEQUENCE OF INTEGER { status_request(5) }
		// Encoded manually per RFC 7633 §4.2.1.
		ext := pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24},
			Value: encodeMustStaple(),
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
}

// encodeMustStaple returns the DER encoding of a SEQUENCE OF INTEGER
// containing exactly one element (5, the status_request feature).
func encodeMustStaple() []byte {
	// Outer SEQUENCE: tag=0x30, length, contents.
	// Inner INTEGER: tag=0x02, length=1, value=0x05.
	return []byte{
		0x30, 0x03, // SEQUENCE, 3 bytes
		0x02, 0x01, 0x05, // INTEGER 5
	}
}

// mustDialer builds a SafeDialer that allows loopback. Used by the
// analyzer integration tests to connect to a TLS server bound to
// 127.0.0.1.
func mustDialer(t *testing.T, _ *x509.CertPool) *security.SafeDialer {
	t.Helper()
	disable := true
	net := config.NetworkPolicy{
		BlockPrivate:         ptr(false),
		BlockLoopback:        ptr(false),
		BlockLinkLocal:       ptr(true),
		BlockMulticast:       ptr(true),
		BlockUnspecified:     ptr(true),
		BlockCloudMeta:       ptr(true),
		AllowIPv4:            ptr(true),
		AllowIPv6:            ptr(false),
		DisableDefaultBogons: disable,
	}
	filter, err := security.NewIPFilter(&net)
	if err != nil {
		t.Fatalf("ip filter: %v", err)
	}
	d, err := security.NewSafeDialer(net, filter, 5*time.Second)
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	return d
}

func ptr[T any](v T) *T { return &v }

// splitHostPort is a small wrapper around net.SplitHostPort that
// allows the test code to keep address parsing in one place.
func splitHostPort(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	return host, port, nil
}

// testContext returns a context with the analyser default budget.
// It is the context passed to phase functions by runOptionalPhases
// in production code.
func testContext(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

// testCancelledContext returns a context already cancelled, so
// phase functions exit early. The returned cancel function is a
// no-op.
func testCancelledContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, cancel
}
