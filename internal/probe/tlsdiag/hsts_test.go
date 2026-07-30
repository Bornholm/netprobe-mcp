// Tests for the HSTS / HTTP-redirect active phase.

package tlsdiag

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// hstsTestServer returns a server that responds on the given path
// with the supplied header values. Use redirectURL to make the
// server answer with a redirect.
func hstsTestServer(t *testing.T, status int, hsts string, redirectURL string) (string, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
			return
		}
		if hsts != "" {
			w.Header().Set("Strict-Transport-Security", hsts)
		}
		w.WriteHeader(status)
	})
	srv := httptest.NewServer(mux)
	return srv.URL, srv.Close
}

// parseHostPort extracts host and port from a httptest URL.
func parseHostPort(t *testing.T, raw string) (string, uint16) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	var p uint16
	for _, c := range port {
		p = p*10 + uint16(c-'0')
	}
	return host, p
}

func TestCheckHSTS_MissingHeader(t *testing.T) {
	url, stop := hstsTestServer(t, http.StatusOK, "", "")
	defer stop()
	host, port := parseHostPort(t, url)
	tgt := &security.SafeTarget{
		Hostname: host,
		IP:       netip.MustParseAddr(host),
		Port:     443,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, nil)
	rep := a.checkHSTS(testContext(t), tgt, DiagnoseOptions{HTTPPort: port})
	if rep.StrictTransportSecurity != "" {
		t.Errorf("expected empty HSTS header, got %q", rep.StrictTransportSecurity)
	}
}

func TestCheckHSTS_PresentHeader(t *testing.T) {
	url, stop := hstsTestServer(t, http.StatusOK, "max-age=31536000; includeSubDomains; preload", "")
	defer stop()
	host, port := parseHostPort(t, url)
	tgt := &security.SafeTarget{
		Hostname: host,
		IP:       netip.MustParseAddr(host),
		Port:     443,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, nil)
	rep := a.checkHSTS(testContext(t), tgt, DiagnoseOptions{HTTPPort: port})
	if rep.MaxAgeSeconds != 31536000 {
		t.Errorf("expected max-age=31536000, got %d", rep.MaxAgeSeconds)
	}
	if !rep.IncludeSubDomains {
		t.Errorf("expected includeSubDomains=true")
	}
	if !rep.Preload {
		t.Errorf("expected preload=true")
	}
}

func TestCheckHSTS_ShortMaxAge(t *testing.T) {
	url, stop := hstsTestServer(t, http.StatusOK, "max-age=3600", "")
	defer stop()
	host, port := parseHostPort(t, url)
	tgt := &security.SafeTarget{
		Hostname: host,
		IP:       netip.MustParseAddr(host),
		Port:     443,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, nil)
	rep := a.checkHSTS(testContext(t), tgt, DiagnoseOptions{HTTPPort: port})
	if !rep.HSTSShortMaxAge {
		t.Errorf("expected HSTSShortMaxAge=true for max-age=3600")
	}
}

func TestCheckHSTS_RedirectHTTPS(t *testing.T) {
	// Server answers on plain HTTP with a redirect to https://
	url, stop := hstsTestServer(t, 0, "", "https://example.com/")
	defer stop()
	host, port := parseHostPort(t, url)
	tgt := &security.SafeTarget{
		Hostname: host,
		IP:       netip.MustParseAddr(host),
		Port:     443,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, nil)
	rep := a.checkHSTS(testContext(t), tgt, DiagnoseOptions{HTTPPort: port})
	// The redirect target is off-host (example.com vs the test
	// server), so CheckRedirect returns http.ErrUseLastResponse and
	// the client surfaces the 301 response. The redirect URL is
	// captured in resp.Header.Get("Location") rather than in
	// resp.Request.URL. The report marks HTTPSRedirect=true when
	// the Location header points to an https:// URL.
	if !rep.HTTPSRedirect {
		t.Errorf("expected HTTPSRedirect=true on 301 to https URL, got %+v", rep)
	}
}

func TestParseHSTS(t *testing.T) {
	var rep HSTSReport
	parseHSTS("max-age=31536000 ; includeSubDomains ; preload", &rep)
	if rep.MaxAgeSeconds != 31536000 {
		t.Errorf("expected 31536000, got %d", rep.MaxAgeSeconds)
	}
	if !rep.IncludeSubDomains || !rep.Preload {
		t.Errorf("expected includeSubDomains+preload=true, got %+v", rep)
	}

	// Case-insensitive match.
	rep = HSTSReport{}
	parseHSTS("MAX-AGE=42", &rep)
	if rep.MaxAgeSeconds != 42 {
		t.Errorf("expected 42, got %d", rep.MaxAgeSeconds)
	}

	// Garbage value: parseHSTS leaves the field untouched.
	rep = HSTSReport{}
	parseHSTS("max-age=not-a-number", &rep)
	if rep.MaxAgeSeconds != 0 {
		t.Errorf("expected 0 for invalid value, got %d", rep.MaxAgeSeconds)
	}
}

func TestSameHostPort(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"example.com:80", "example.com:80", true},
		{"example.com:80", "EXAMPLE.com:80", true},
		{"example.com:80", "example.com:443", false},
		{"example.com:80", "other.com:80", false},
		{"malformed", "example.com:80", false},
	}
	for _, c := range cases {
		if got := sameHostPort(c.a, c.b); got != c.want {
			t.Errorf("sameHostPort(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
