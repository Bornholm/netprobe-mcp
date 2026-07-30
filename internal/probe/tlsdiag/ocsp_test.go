package tlsdiag

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestAnalyzeStapledOCSP_Good(t *testing.T) {
	leaf, inter, _, pool, _, interKey, _ := buildChainFull(t, nil)
	now := testClock()
	resp := makeOCSP(t, leaf, inter, interKey, ocsp.Good, now.Add(-time.Hour), now.Add(7*24*time.Hour), 0)
	_ = pool
	rep := analyzeStapledOCSP(leaf, []*x509.Certificate{leaf, inter}, resp, now)
	if !rep.Stapled {
		t.Errorf("expected Stapled=true")
	}
	if rep.StapleStatus != "good" {
		t.Errorf("expected status=good, got %s", rep.StapleStatus)
	}
	if rep.StapleSigValid == nil || !*rep.StapleSigValid {
		t.Errorf("expected StapleSigValid=true")
	}
}

func TestAnalyzeStapledOCSP_Revoked(t *testing.T) {
	leaf, inter, _, _, _, interKey, _ := buildChainFull(t, nil)
	now := testClock()
	resp := makeOCSP(t, leaf, inter, interKey, ocsp.Revoked, now.Add(-time.Hour), now.Add(7*24*time.Hour), ocsp.KeyCompromise)
	rep := analyzeStapledOCSP(leaf, []*x509.Certificate{leaf, inter}, resp, now)
	if rep.StapleStatus != "revoked" {
		t.Errorf("expected revoked, got %s", rep.StapleStatus)
	}
	if rep.RevocationReason != "key_compromise" {
		t.Errorf("expected reason=key_compromise, got %s", rep.RevocationReason)
	}
}

func TestAnalyzeStapledOCSP_Expired(t *testing.T) {
	leaf, inter, _, _, _, interKey, _ := buildChainFull(t, nil)
	now := testClock()
	resp := makeOCSP(t, leaf, inter, interKey, ocsp.Good, now.Add(-7*24*time.Hour), now.Add(-time.Hour), 0)
	rep := analyzeStapledOCSP(leaf, []*x509.Certificate{leaf, inter}, resp, now)
	if !rep.StapleExpired {
		t.Errorf("expected StapleExpired=true")
	}
}

func TestAnalyzeStapledOCSP_NoStaple(t *testing.T) {
	leaf, _, _, _, _, _, _ := buildChainFull(t, nil)
	rep := analyzeStapledOCSP(leaf, []*x509.Certificate{leaf}, nil, testClock())
	if rep.Stapled {
		t.Errorf("expected Stapled=false when no OCSP response is presented")
	}
	if rep.StapleStatus != "" {
		t.Errorf("expected empty status, got %s", rep.StapleStatus)
	}
}

func TestAnalyzeStapledOCSP_InvalidSig(t *testing.T) {
	leaf, inter, _, _, _, _, _ := buildChainFull(t, nil)
	now := testClock()
	// Sign with a key unrelated to the issuer.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   now.Add(-time.Hour),
		NextUpdate:   now.Add(7 * 24 * time.Hour),
	}
	der, err := ocsp.CreateResponse(inter, inter, tmpl, wrongKey)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	rep := analyzeStapledOCSP(leaf, []*x509.Certificate{leaf, inter}, der, now)
	if rep.StapleSigValid == nil || *rep.StapleSigValid {
		t.Errorf("expected StapleSigValid=false (got sigValid=%v)", rep.StapleSigValid)
	}
}

func TestRevocationReasonString(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "unspecified"},
		{1, "key_compromise"},
		{2, "ca_compromise"},
		{99, "unknown"},
	}
	for _, c := range cases {
		if got := revocationReasonString(c.in); got != c.want {
			t.Errorf("revocationReasonString(%d) = %s, want %s", c.in, got, c.want)
		}
	}
}

// --- helpers ---

// makeOCSP builds and signs an OCSP response. The signer is the
// issuer's private key, so the response is verifiable.
func makeOCSP(t *testing.T, leaf, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, status int, thisUpdate, nextUpdate time.Time, reason int) []byte {
	t.Helper()
	tmpl := ocsp.Response{
		Status:       status,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
	}
	if status == ocsp.Revoked {
		tmpl.RevokedAt = thisUpdate
		tmpl.RevocationReason = reason
	}
	der, err := ocsp.CreateResponse(issuer, issuer, tmpl, issuerKey)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	return der
}
