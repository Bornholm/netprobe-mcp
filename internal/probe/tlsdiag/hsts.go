// HSTS and HTTP-to-HTTPS redirect check. Issues a single GET-style
// HEAD request to the target on the dedicated HTTPPort (default 80)
// and inspects:
//
//   - Whether the response (or its redirects) ends on the
//     TLS endpoint (HTTPS redirect).
//   - The presence and value of the Strict-Transport-Security header.
//   - Whether HSTS is delivered on plain HTTP (suspicious but
//     ignored by clients).
//
// The request is read-only and bounded in bytes; no body is
// returned to the caller.

package tlsdiag

import (
	"context"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// hstsMinMaxAge is the recommended minimum max-age value: 180 days.
const hstsMinMaxAge = int64(15552000)

// checkHSTS issues a single HEAD request to the HTTPPort and parses
// the Strict-Transport-Security header. Redirects are followed up to
// three hops (governed by the http.Client) but only when the redirect
// target stays within the same host.
//
// The function returns an HSTSReport with the observed state. The
// caller decides how to surface a failed probe.
func (a *Analyzer) checkHSTS(ctx context.Context, target *security.SafeTarget, opts DiagnoseOptions) HSTSReport {
	port := opts.HTTPPort
	if port == 0 {
		port = 80
	}
	rep := HSTSReport{}

	// Build a SafeTarget clone for the HTTP port so the pinned
	// dialer validates the HTTPPort tuple correctly. We copy
	// field-by-field to avoid copying the embedded sync.Once
	// (go vet catches this).
	httpTarget := &security.SafeTarget{
		Hostname: target.Hostname,
		IP:       target.IP,
		AllIPs:   target.AllIPs,
		Port:     port,
		Scheme:   target.Scheme,
	}

	dialFn := a.dialer.PinnedDialContext(httpTarget)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialFn(ctx, network, net.JoinHostPort(httpTarget.Hostname, strconv.Itoa(int(port))))
		},
		DisableKeepAlives:      true,
		MaxIdleConns:           0,
		IdleConnTimeout:        1 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			// Refuse off-host redirects to limit probe scope.
			if len(via) > 0 {
				prev := via[len(via)-1].URL.Host
				if !sameHostPort(req.URL.Host, prev) {
					return http.ErrUseLastResponse
				}
			}
			return nil
		},
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, "http://"+net.JoinHostPort(target.Hostname, strconv.Itoa(int(port)))+"/", nil)
	if err != nil {
		rep.Note = "could not build HSTS request: " + err.Error()
		return rep
	}
	resp, err := client.Do(req)
	if err != nil {
		rep.Note = "HSTS check failed: " + err.Error()
		return rep
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, int64(a.cfg.MaxHSTSBytes)))
		_ = resp.Body.Close()
	}()

	// Determine HTTPS redirect: at least one redirect to an
	// https:// location. The header is the most reliable signal
	// when redirects were stopped early.
	rep.HTTPSRedirect = false
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Scheme == "https" {
		rep.HTTPSRedirect = true
	}
	if !rep.HTTPSRedirect {
		if loc := resp.Header.Get("Location"); loc != "" {
			if u, perr := neturl.Parse(loc); perr == nil && u.Scheme == "https" {
				rep.HTTPSRedirect = true
			}
		}
	}

	if val := resp.Header.Get("Strict-Transport-Security"); val != "" {
		if resp.Request.URL != nil && resp.Request.URL.Scheme == "http" {
			rep.HSTSOnHTTP = true
		}
		rep.StrictTransportSecurity = val
		parseHSTS(val, &rep)
		rep.HSTSShortMaxAge = rep.MaxAgeSeconds > 0 && rep.MaxAgeSeconds < hstsMinMaxAge
	}

	return rep
}

// parseHSTS extracts max-age, includeSubDomains and preload from a
// Strict-Transport-Security header value. Tokens are split on ";"
// and the directives are case-insensitive (RFC 6797 §6.1).
func parseHSTS(value string, rep *HSTSReport) {
	for _, tok := range strings.Split(value, ";") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		lower := strings.ToLower(tok)
		switch {
		case strings.HasPrefix(lower, "max-age="):
			numStr := strings.TrimSpace(tok[len("max-age="):])
			if n, err := strconv.ParseInt(numStr, 10, 64); err == nil {
				rep.MaxAgeSeconds = n
			}
		case lower == "includesubdomains":
			rep.IncludeSubDomains = true
		case lower == "preload":
			rep.Preload = true
		}
	}
}

// sameHostPort compares two "host:port" strings for the same
// hostname+port tuple, ignoring leading/trailing whitespace and
// case on the host.
func sameHostPort(a, b string) bool {
	ah, ap, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	bh, bp, err := net.SplitHostPort(b)
	if err != nil {
		return false
	}
	return strings.EqualFold(ah, bh) && ap == bp
}
