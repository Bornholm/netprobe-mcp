// AIA (Authority Information Access) chasing. When the presented
// chain fails to validate against the trust pool and the failure
// looks like a missing intermediate, the analyser MAY follow the
// IssuingCertificateURL pointers to retrieve the missing
// certificate(s) and re-verify the chain.
//
// AIA chasing is a SECONDARY SSRF channel — the URL is taken from
// the certificate presented by the target, which an attacker
// controls. To neutralise that risk:
//
//   1. The Diagnose path requires BOTH DiagnoseOptions.AIAFetch
//      AND cfg.AllowAIAFetch to be true. The config knob stays
//      false by default (v1 hard-off) and configuration validation
//      rejects any non-false value at boot.
//   2. Each URL is re-authorised through the Guard pipeline with
//      Purpose=security.PurposeAIAFetch so the regular allow-list
//      applies (with the operator's explicit purposes annotation).
//   3. The fetcher caps the number of URLs and the bytes per fetch.
//
// In v1 the active AIA path is gated behind a configuration knob
// (AllowAIAFetch) so it cannot be accidentally enabled through a
// policy mistake. This file still implements the path so flipping
// the knob in a future release wires it up.

package tlsdiag

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// fetchAIA attempts to retrieve the missing intermediate(s) from
// the AIA URLs listed in the leaf certificate. On success the
// chain report is updated to reflect the freshly built chain; on
// refusal (no matching allow-list rule) a SkippedCheck entry is
// added so the LLM understands why the chain stayed incomplete.
//
// The function never returns an error; failures are recorded
// inline on the report.
func (a *Analyzer) fetchAIA(ctx context.Context, target *security.SafeTarget, presented []*x509.Certificate, rep *Report) {
	if a.guard == nil {
		return
	}
	if len(presented) == 0 {
		return
	}
	leaf := presented[0]
	urls := leaf.IssuingCertificateURL
	if len(urls) == 0 {
		return
	}
	limit := a.cfg.MaxAIAFetches
	if limit <= 0 || limit > len(urls) {
		limit = len(urls)
	}

	fetched := make([]*x509.Certificate, 0, limit)
	for i := 0; i < limit; i++ {
		rawURL := urls[i]
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		if !strings.EqualFold(u.Scheme, "http") {
			// Per RFC 5280 §4.2.2.1, AIA URLs use http://
			// (despite the obvious downgrade risk). Reject anything
			// else, including https.
			continue
		}
		port := uint16(80)
		if p := u.Port(); p != "" {
			n, perr := strconv.ParseUint(p, 10, 16)
			if perr != nil {
				continue
			}
			port = uint16(n)
		}
		host := u.Hostname()
		if host == "" {
			continue
		}

		// Re-authorise the AIA URL through the Guard pipeline. The
		// dedicated Purpose forces the operator to whitelist AIA
		// destinations independently of regular probe targets.
		fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		aiaTarget, aerr := a.guard.Authorize(fetchCtx, security.Request{
			Tool:      "tls_diagnose:aia_fetch",
			SessionID: "",
			Scheme:    "http",
			Host:      host,
			Port:      port,
			Path:      u.Path,
			Purpose:   security.PurposeAIAFetch,
		})
		cancel()
		if aerr != nil {
			rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
				Check:  "TLS_AIA_FETCH",
				Reason: "denied by policy: " + sanitizeAIAURL(rawURL),
			})
			rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
				URL:     sanitizeAIAURL(rawURL),
				Purpose: "aia_fetch",
				Outcome: "denied",
				Reason:  aerr.Error(),
			})
			continue
		}

		body, ferr := a.singleAIAFetch(ctx, aiaTarget, u.Path)
		aiaTarget.Release()
		if ferr != nil {
			rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
				Check:  "TLS_AIA_FETCH",
				Reason: "fetch failed for " + sanitizeAIAURL(rawURL) + ": " + ferr.Error(),
			})
			rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
				URL:     sanitizeAIAURL(rawURL),
				Purpose: "aia_fetch",
				Outcome: "error",
				Reason:  ferr.Error(),
			})
			continue
		}
		cert, perr := x509.ParseCertificate(body)
		if perr != nil {
			rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
				Check:  "TLS_AIA_FETCH",
				Reason: "parse failed for " + sanitizeAIAURL(rawURL) + ": " + perr.Error(),
			})
			rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
				URL:       sanitizeAIAURL(rawURL),
				Purpose:   "aia_fetch",
				Outcome:   "error",
				BytesRead: int64(len(body)),
				Reason:    "parse: " + perr.Error(),
			})
			continue
		}
		rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
			URL:       sanitizeAIAURL(rawURL),
			Purpose:   "aia_fetch",
			Outcome:   "success",
			BytesRead: int64(len(body)),
		})
		fetched = append(fetched, cert)
	}

	if len(fetched) == 0 {
		return
	}

	// Rebuild the chain pool with the freshly-fetched certificates
	// and re-run verification.
	intermediates := x509.NewCertPool()
	for _, c := range presented[1:] {
		intermediates.AddCert(c)
	}
	for _, c := range fetched {
		intermediates.AddCert(c)
	}

	opts := x509.VerifyOptions{
		DNSName:       target.Hostname,
		Intermediates: intermediates,
		Roots:         a.rootPool(),
		CurrentTime:   a.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := leaf.Verify(opts); err == nil {
		rep.Chain.Complete = true
		rep.Chain.MissingIntermediate = true
	}
}

// singleAIAFetch performs a single HTTP GET against the AIA URL,
// using the pinned dialer to honour the resolved IP. Returns the raw
// DER bytes read from the body; the caller parses them. Returning
// bytes (rather than a *x509.Certificate) lets the caller record the
// byte count for the audit log even when parsing eventually fails.
func (a *Analyzer) singleAIAFetch(ctx context.Context, aiaTarget *security.SafeTarget, path string) ([]byte, error) {
	if aiaTarget == nil || a.dialer == nil {
		return nil, fmt.Errorf("aia: target or dialer not available")
	}
	dialFn := a.dialer.PinnedDialContext(aiaTarget)
	transport := &http.Transport{
		DialContext:           dialFn,
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
		IdleConnTimeout:       1 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+net.JoinHostPort(aiaTarget.Hostname, strconv.Itoa(int(aiaTarget.Port)))+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("aia: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, int64(a.cfg.MaxAIABytes)))
}

// sanitizeAIAURL reduces a URL to scheme://host:port/path for safe
// logging. The function never panics.
func sanitizeAIAURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable)"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// optsHostnameOrServerName kept for future use when SafeTarget
// grows a ServerName field; v1 always uses Hostname.
func optsHostnameOrServerName(target *security.SafeTarget) string {
	return target.Hostname
}
