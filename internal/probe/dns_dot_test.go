package probe

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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startDoTServer starts an in-memory DNS-over-TLS server using a freshly
// generated self-signed certificate. Returns the listen address and the
// CA pool to use for client verification. Each call regenerates the cert
// (and matching pool), so tests under -count=N get a fresh matching pair.
func startDoTServer(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1").To4(),
			},
		}
		_ = w.WriteMsg(resp)
	}))
	srv := &dns.Server{Listener: ln, Handler: mux, TLSConfig: tlsCfg}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatalf("DoT server failed to start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	return ln.Addr().String(), pool
}

// sharedDoTCertPool is kept for backwards compatibility with code that
// expects it (none currently does). The actual DoT test rebuilds a fresh
// pool on every run to avoid stale-cert matches under -count=N.
var (
	_                 = sync.Once{}
	sharedDoTCertPool *x509.CertPool
	sharedDoTCertOnce sync.Once
	sharedDoTCert     tls.Certificate
	sharedDoTCertDER  []byte
)

func TestDNSProber_Run_DoT(t *testing.T) {
	addr, pool := startDoTServer(t)
	cfg := configStub()
	cfg.AllowDoT = true
	p := NewDNSProberFromConfig(cfg, 0, 2*time.Second)
	p.SetRootCAs(pool)
	tgt := testSafeTarget(addr, "dot")
	tgt.Hostname = "localhost"
	res, err := p.Run(context.Background(), tgt, DNSOptions{
		Name:      "example.com",
		QueryType: "A",
		Protocol:  "tcp-tls",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected DoT success, got %+v", res)
	}
	if len(res.DNS.Answers) != 1 {
		t.Fatalf("expected one answer, got %d", len(res.DNS.Answers))
	}
	if !strings.HasSuffix(res.DNS.Answers[0].Data, ".1") && res.DNS.Answers[0].Data != "127.0.0.1" {
		t.Fatalf("unexpected answer: %q", res.DNS.Answers[0].Data)
	}
}
