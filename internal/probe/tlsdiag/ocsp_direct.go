// Direct OCSP query. Sends a single POST request to the OCSP
// responder URL advertised in the leaf certificate and parses the
// response. Same SSRF concerns as AIA chasing; same gating
// mechanism (DiagnoseOptions.OCSPDirect AND cfg.AllowOCSPQuery).

package tlsdiag

import (
	"bytes"
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
	"golang.org/x/crypto/ocsp"
)

// queryOCSPDirect posts a fresh OCSP request to the responder URL
// listed in the leaf certificate, then parses the response and
// attaches the result to the report.
//
// Failures (denied by policy, network error, parse error) are
// recorded in the existing OCSPReport (when there is one) or in
// SkippedCheck so the LLM sees what happened.
func (a *Analyzer) queryOCSPDirect(ctx context.Context, target *security.SafeTarget, presented []*x509.Certificate, rep *Report) {
	if a.guard == nil || len(presented) == 0 {
		return
	}
	leaf := presented[0]
	if len(leaf.OCSPServer) == 0 {
		rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
			Check:  "TLS_OCSP_DIRECT_QUERY",
			Reason: "leaf certificate declares no OCSP responder URL",
		})
		return
	}

	// Find an issuer to sign the OCSP request with. In v1 the
	// request is unsigned; many responders accept unsigned
	// requests, but some (notably Let's Encrypt) reject them. The
	// signed path can be added when a private key for the issuer is
	// available — typically via a configured CA pool. For now we
	// send an unsigned request.
	issuer := findIssuer(presented, leaf)
	if issuer == nil {
		rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
			Check:  "TLS_OCSP_DIRECT_QUERY",
			Reason: "no issuer certificate available to sign OCSP request",
		})
		return
	}

	rawURL := leaf.OCSPServer[0]
	u, err := url.Parse(rawURL)
	if err != nil {
		rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
			Check:  "TLS_OCSP_DIRECT_QUERY",
			Reason: "OCSP URL unparseable: " + sanitizeAIAURL(rawURL),
		})
		rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
			URL:     sanitizeAIAURL(rawURL),
			Purpose: "ocsp_query",
			Outcome: "error",
			Reason:  "unparseable URL",
		})
		return
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
			Check:  "TLS_OCSP_DIRECT_QUERY",
			Reason: "unsupported OCSP URL scheme: " + u.Scheme,
		})
		rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
			URL:     sanitizeAIAURL(rawURL),
			Purpose: "ocsp_query",
			Outcome: "error",
			Reason:  "unsupported scheme: " + u.Scheme,
		})
		return
	}
	port := uint16(80)
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, perr := strconv.ParseUint(p, 10, 16)
		if perr != nil {
			rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
				URL:     sanitizeAIAURL(rawURL),
				Purpose: "ocsp_query",
				Outcome: "error",
				Reason:  "unparseable port",
			})
			return
		}
		port = uint16(n)
	}
	host := u.Hostname()
	if host == "" {
		rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
			URL:     sanitizeAIAURL(rawURL),
			Purpose: "ocsp_query",
			Outcome: "error",
			Reason:  "empty host",
		})
		return
	}

	// Re-authorise the OCSP URL through the Guard pipeline.
	authCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ocspTarget, err := a.guard.Authorize(authCtx, security.Request{
		Tool:      "tls_diagnose:ocsp_direct",
		SessionID: "",
		Scheme:    u.Scheme,
		Host:      host,
		Port:      port,
		Path:      u.Path,
		Purpose:   security.PurposeOCSPQuery,
	})
	cancel()
	if err != nil {
		rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
			Check:  "TLS_OCSP_DIRECT_QUERY",
			Reason: "denied by policy: " + sanitizeAIAURL(rawURL),
		})
		rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
			URL:     sanitizeAIAURL(rawURL),
			Purpose: "ocsp_query",
			Outcome: "denied",
			Reason:  err.Error(),
		})
		return
	}
	defer ocspTarget.Release()

	// Build a minimal unsigned OCSP request.
	reqBytes, err := buildOCSPRequest(leaf, issuer)
	if err != nil {
		rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
			Check:  "TLS_OCSP_DIRECT_QUERY",
			Reason: "build OCSP request: " + err.Error(),
		})
		rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
			URL:     sanitizeAIAURL(rawURL),
			Purpose: "ocsp_query",
			Outcome: "error",
			Reason:  "build: " + err.Error(),
		})
		return
	}

	respBytes, err := a.postOCSP(ctx, ocspTarget, reqBytes)
	if err != nil {
		rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
			Check:  "TLS_OCSP_DIRECT_QUERY",
			Reason: "POST failed: " + err.Error(),
		})
		rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
			URL:     sanitizeAIAURL(rawURL),
			Purpose: "ocsp_query",
			Outcome: "error",
			Reason:  err.Error(),
		})
		return
	}

	parsed, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		rep.ChecksSkipped = append(rep.ChecksSkipped, SkippedCheck{
			Check:  "TLS_OCSP_DIRECT_QUERY",
			Reason: "parse response: " + err.Error(),
		})
		rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
			URL:       sanitizeAIAURL(rawURL),
			Purpose:   "ocsp_query",
			Outcome:   "error",
			BytesRead: int64(len(respBytes)),
			Reason:    "parse: " + err.Error(),
		})
		return
	}

	rep.OutboundRequests = append(rep.OutboundRequests, OutboundRequest{
		URL:       sanitizeAIAURL(rawURL),
		Purpose:   "ocsp_query",
		Outcome:   "success",
		BytesRead: int64(len(respBytes)),
	})

	if rep.OCSP == nil {
		rep.OCSP = &OCSPReport{}
	}
	rep.OCSP.DirectQueried = true
	rep.OCSP.DirectStatus = ocspStatusString(parsed.Status)
	rep.OCSP.DirectError = ""
	if parsed.Status == ocsp.Revoked {
		rep.OCSP.RevokedAt = &parsed.RevokedAt
		rep.OCSP.RevocationReason = revocationReasonString(parsed.RevocationReason)
	}
}

// postOCSP sends a POST application/ocsp-request to the OCSP
// responder and returns the raw response body. The dialer is
// pinned to the validated SafeTarget IP.
func (a *Analyzer) postOCSP(ctx context.Context, target *security.SafeTarget, body []byte) ([]byte, error) {
	dialFn := a.dialer.PinnedDialContext(target)
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
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		net.JoinHostPort(target.Hostname, strconv.Itoa(int(target.Port)))+"/",
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("OCSP responder: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, int64(a.cfg.MaxOCSPBytes)))
}

// buildOCSPRequest creates a minimal unsigned OCSP request asking
// for the status of cert. issuer is currently unused but kept in
// the signature so a future signed-request implementation can plug
// in without changing call sites.
func buildOCSPRequest(cert, issuer *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("missing cert")
	}
	_ = issuer
	req := ocsp.Request{
		SerialNumber: cert.SerialNumber,
	}
	return req.Marshal()
}

// findIssuer returns the issuer of cert from the presented chain,
// or nil if not present.
func findIssuer(presented []*x509.Certificate, cert *x509.Certificate) *x509.Certificate {
	for _, c := range presented {
		if c == cert {
			continue
		}
		if c.Subject.String() == cert.Issuer.String() {
			return c
		}
	}
	return nil
}

// ocspStatusString maps an OCSP status code to a stable label.
func ocspStatusString(s int) string {
	switch s {
	case 0:
		return "good"
	case 1:
		return "revoked"
	case 2:
		return "unknown"
	}
	return "unknown"
}
