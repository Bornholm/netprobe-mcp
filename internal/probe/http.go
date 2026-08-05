package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/security"
)

// HTTPOptions are the agent-facing parameters of http_probe.
type HTTPOptions struct {
	URL                  string            `json:"url" jsonschema:"absolute http or https URL"`
	Method               string            `json:"method,omitempty" jsonschema:"HTTP method; GET or HEAD"`
	Headers              map[string]string `json:"headers,omitempty" jsonschema:"request headers; allow-listed names only (no Authorization)"`
	TimeoutMs            int               `json:"timeout_ms,omitempty" jsonschema:"per-request timeout in milliseconds"`
	FollowRedirects      *bool             `json:"follow_redirects,omitempty"`
	MaxRedirects         int               `json:"max_redirects,omitempty" jsonschema:"maximum number of redirects; 0 disables following"`
	ExpectedStatusCodes  []int             `json:"expected_status_codes,omitempty"`
	FailIfBodyMatches    []string          `json:"fail_if_body_matches,omitempty" jsonschema:"regexps that must NOT match the body"`
	FailIfBodyNotMatches []string          `json:"fail_if_body_not_matches,omitempty" jsonschema:"regexps that MUST match the body"`
	ReturnBodySnippet    bool              `json:"return_body_snippet,omitempty"`
	IncludeTLSInfo       bool              `json:"include_tls_info,omitempty"`
}

// HTTPResult is the agent-facing structured output of an HTTP probe.
type HTTPResult struct {
	StatusCode      int               `json:"status_code"`
	StatusText      string            `json:"status_text"`
	Proto           string            `json:"proto"`
	ContentLength   int64             `json:"content_length,omitempty"`
	BodyBytesRead   int64             `json:"body_bytes_read"`
	BodyTruncated   bool              `json:"body_truncated"`
	BodySnippet     string            `json:"body_snippet,omitempty"`
	BodySHA256      string            `json:"body_sha256,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	RejectedHeaders []RejectedHeader  `json:"rejected_headers,omitempty"`
	Hops            []HopResult       `json:"hops,omitempty"`
	RedirectCount   int               `json:"redirect_count"`
	RedirectBlocked *BlockedRedirect  `json:"redirect_blocked,omitempty"`
	Checks          []CheckResult     `json:"checks,omitempty"`
	TLS             *TLSPassiveInfo   `json:"tls,omitempty"`
}

// HopResult records the resolution and timing of a single hop in a redirect chain.
type HopResult struct {
	URL        string  `json:"url"`
	StatusCode int     `json:"status_code"`
	ResolvedIP string  `json:"resolved_ip"`
	DurationMs float64 `json:"duration_ms"`
}

// BlockedRedirect records a redirect that the Guard pipeline refused.
type BlockedRedirect struct {
	Target     string `json:"target"`
	Category   string `json:"category"`
	Reason     string `json:"reason"`
	StatusCode int    `json:"status_code"`
}

// CheckResult is one assertion evaluated against the probe's response.
type CheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details,omitempty"`
}

// TLSPassiveInfo captures non-destructive observations from the handshake.
type TLSPassiveInfo struct {
	Version           string  `json:"version"`
	CipherSuite       string  `json:"cipher_suite"`
	NegotiatedALPN    string  `json:"alpn,omitempty"`
	FingerprintSHA256 string  `json:"peer_cert_sha256"`
	DaysUntilExpiry   float64 `json:"days_until_expiry"`
	NotBefore         string  `json:"not_before,omitempty"`
	NotAfter          string  `json:"not_after,omitempty"`
	Subject           string  `json:"subject,omitempty"`
	Issuer            string  `json:"issuer,omitempty"`
	SANCount          int     `json:"san_count,omitempty"`
}

// AllowedMethods is the closed set of HTTP methods http_probe may issue.
// Bodies are never sent; HEAD and GET are the only safe verbs.
var AllowedMethods = map[string]bool{
	http.MethodGet:  true,
	http.MethodHead: true,
}

// forbiddenRequestHeaders is the unconditional blocklist of header names
// the agent must never send through http_probe. These either leak
// credentials (Authorization, Cookie), enable virtual-host confusion
// (Host, X-Forwarded-Host), let the caller impersonate internal
// infrastructure (X-Forwarded-For, X-Real-IP, Forwarded), or are
// hop-by-hop headers whose injection could enable request smuggling
// (Transfer-Encoding, Content-Length, Connection, Upgrade).
//
// The blocklist is applied even when the operator's allow-list would
// otherwise permit the name — defense in depth, mirroring the design
// decision documented in PLAN.md §7.2 and §13.6.
var forbiddenRequestHeaders = map[string]bool{
	"host":                true,
	"authorization":       true,
	"cookie":              true,
	"proxy-authorization": true,
	"proxy-connection":    true,
	"x-forwarded-for":     true,
	"x-forwarded-host":    true,
	"x-forwarded-proto":   true,
	"x-forwarded-port":    true,
	"x-real-ip":           true,
	"forwarded":           true,
	"connection":          true,
	"upgrade":             true,
	"transfer-encoding":   true,
	"content-length":      true,
	"expect":              true,
	"te":                  true,
	"trailer":             true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"www-authenticate":    true,
}

// RejectedHeader records one header that the caller tried to set but
// the policy refused. Returned in HTTPResult so the agent understands
// which entries were silently dropped.
type RejectedHeader struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// ErrInvalidRequest indicates the LLM supplied parameters the tool cannot act
// on. The handler translates this into IsError=true (refusal of the call, not
// a probe result).
type ErrInvalidRequest struct {
	Reason string
}

func (e *ErrInvalidRequest) Error() string { return e.Reason }

// ErrRedirectBlocked is returned by the redirect revalidator when a Location
// fails the Guard pipeline. It is reported as an observation, not as a tool
// error.
type ErrRedirectBlocked struct {
	Target   string
	Category string
	Reason   string
	Status   int
}

func (e *ErrRedirectBlocked) Error() string {
	return fmt.Sprintf("redirect to %q blocked: %s", e.Target, e.Reason)
}

// HTTPProberConfig is the static, validated configuration of the prober.
type HTTPProberConfig struct {
	MaxBodyBytes     int64
	MaxReturnedBytes int64
	HeaderAllowList  []string
	MaxRedirects     int
	// RootCAs, if non-nil, replaces the system trust store. Used by tests
	// that need to trust a self-signed certificate generated by httptest.
	// Production code MUST leave this nil so the system trust anchors are
	// used.
	RootCAs *x509.CertPool
}

// HTTPProber performs a single HTTP(S) probe. The destination has already
// been authorized by the Guard pipeline; this type never re-resolves the host.
type HTTPProber struct {
	cfg     HTTPProberConfig
	timeout time.Duration
}

// NewHTTPProber builds a prober from the validated config.
func NewHTTPProber(cfg HTTPProberConfig, timeout time.Duration) *HTTPProber {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.MaxReturnedBytes <= 0 {
		cfg.MaxReturnedBytes = 4096
	}
	if cfg.MaxReturnedBytes > cfg.MaxBodyBytes {
		cfg.MaxReturnedBytes = cfg.MaxBodyBytes
	}
	if cfg.MaxRedirects < 0 {
		cfg.MaxRedirects = 0
	}
	allow := make([]string, len(cfg.HeaderAllowList))
	for i, h := range cfg.HeaderAllowList {
		allow[i] = strings.ToLower(strings.TrimSpace(h))
	}
	return &HTTPProber{cfg: HTTPProberConfig{
		MaxBodyBytes:     cfg.MaxBodyBytes,
		MaxReturnedBytes: cfg.MaxReturnedBytes,
		HeaderAllowList:  allow,
		MaxRedirects:     cfg.MaxRedirects,
		RootCAs:          cfg.RootCAs,
	}, timeout: timeout}
}

// NewHTTPProberFromConfig is a convenience constructor used by main.
func NewHTTPProberFromConfig(cfg config.HTTPProbeConfig, timeout time.Duration) *HTTPProber {
	return NewHTTPProber(HTTPProberConfig{
		MaxBodyBytes:     cfg.MaxBodyBytes,
		MaxReturnedBytes: cfg.MaxReturnedBytes,
		HeaderAllowList:  cfg.HeaderAllowList,
		MaxRedirects:     cfg.MaxRedirects,
	}, timeout)
}

// Validate checks the agent-supplied options against the policy.
func (p *HTTPProber) Validate(opts *HTTPOptions) error {
	if opts == nil {
		return &ErrInvalidRequest{Reason: "missing options"}
	}
	if opts.URL == "" {
		return &ErrInvalidRequest{Reason: "url is required"}
	}
	u, err := url.Parse(opts.URL)
	if err != nil {
		return &ErrInvalidRequest{Reason: "url is malformed"}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return &ErrInvalidRequest{Reason: "scheme must be http or https"}
	}
	if u.Host == "" {
		return &ErrInvalidRequest{Reason: "url host is required"}
	}
	if opts.Method == "" {
		opts.Method = http.MethodGet
	}
	if !AllowedMethods[opts.Method] {
		return &ErrInvalidRequest{Reason: "method " + opts.Method + " is not permitted (only GET or HEAD)"}
	}
	for k := range opts.Headers {
		lk := strings.ToLower(strings.TrimSpace(k))
		if forbiddenRequestHeaders[lk] {
			return &ErrInvalidRequest{Reason: "header '" + k + "' is forbidden (security-critical header)"}
		}
		if strings.ContainsAny(k, ":\r\n\x00") || strings.ContainsAny(opts.Headers[k], "\r\n\x00") {
			return &ErrInvalidRequest{Reason: "header '" + k + "' contains invalid characters (CRLF/NUL injection)"}
		}
		if len(opts.Headers[k]) > 1024 {
			return &ErrInvalidRequest{Reason: "header '" + k + "' value exceeds 1024 bytes"}
		}
		if !p.headerAllowed(lk) {
			return &ErrInvalidRequest{Reason: "header '" + k + "' is not in the allow-list"}
		}
	}
	if opts.TimeoutMs < 0 {
		return &ErrInvalidRequest{Reason: "timeout_ms cannot be negative"}
	}
	if opts.TimeoutMs > int(p.timeout/time.Millisecond)*10 {
		// soft cap: do not let the LLM blow the global timeout budget
		opts.TimeoutMs = int(p.timeout / time.Millisecond)
	}
	if opts.MaxRedirects < 0 {
		return &ErrInvalidRequest{Reason: "max_redirects cannot be negative"}
	}
	if opts.MaxRedirects > p.cfg.MaxRedirects {
		opts.MaxRedirects = p.cfg.MaxRedirects
	}
	for _, re := range opts.FailIfBodyMatches {
		if _, err := regexp.Compile(re); err != nil {
			return &ErrInvalidRequest{Reason: "invalid fail_if_body_matches regexp: " + re}
		}
	}
	for _, re := range opts.FailIfBodyNotMatches {
		if _, err := regexp.Compile(re); err != nil {
			return &ErrInvalidRequest{Reason: "invalid fail_if_body_not_matches regexp: " + re}
		}
	}
	return nil
}

func (p *HTTPProber) headerAllowed(lowerName string) bool {
	for _, h := range p.cfg.HeaderAllowList {
		if h == lowerName {
			return true
		}
	}
	return false
}

// Run performs a single HTTP request and returns the structured result. It
// never re-resolves the hostname: the dialer is pinned to target.IP. If
// allowRedirect is true and a Location points to a target the Guard refuses,
// the probe reports it as RedirectBlocked, not as a tool error.
func (p *HTTPProber) Run(
	ctx context.Context,
	target *security.SafeTarget,
	dialer *security.SafeDialer,
	opts HTTPOptions,
	allowRedirect bool,
	guard *security.Guard,
) (*Result, error) {
	start := Now()

	if opts.TimeoutMs <= 0 {
		opts.TimeoutMs = int(p.timeout / time.Millisecond)
	}
	if opts.TimeoutMs > int(p.timeout/time.Millisecond) {
		opts.TimeoutMs = int(p.timeout / time.Millisecond)
	}

	pctx, cancel := context.WithTimeout(ctx, time.Duration(opts.TimeoutMs)*time.Millisecond)
	defer cancel()

	rev := &redirectRevalidator{
		guard:  guard,
		max:    p.cfg.MaxRedirects,
		allow:  allowRedirect,
		cur:    target,
		dialer: dialer,
		ctx:    pctx,
	}
	if !allowRedirect {
		rev.max = 0
	}

	client := p.newClient(dialer, rev, target)

	req, err := http.NewRequestWithContext(pctx, opts.Method, opts.URL, nil)
	if err != nil {
		return p.errorResult(target, opts, err, time.Since(start)), nil
	}
	rejectedHeaders := p.applyHeaders(req, opts.Headers)

	var connectStart, tlsStart, firstByte time.Time
	trace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) {
			connectStart = time.Now()
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			if !tlsStart.IsZero() {
				rev.recordTLS(time.Since(tlsStart))
			}
		},
		GotFirstResponseByte: func() {
			if firstByte.IsZero() {
				firstByte = time.Now()
				if !connectStart.IsZero() {
					rev.recordConnect(time.Since(connectStart))
				}
				if !firstByte.IsZero() {
					rev.recordFirstByte(time.Since(connectStart))
				}
			}
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(pctx, trace))
	resp, err := client.Do(req)
	if err != nil {
		var rerr *ErrRedirectBlocked
		if errors.As(err, &rerr) {
			res := p.redirectBlockedResult(target, opts, rerr, time.Since(start))
			return res, nil
		}
		return p.errorResult(target, opts, err, time.Since(start)), nil
	}
	defer resp.Body.Close()

	bodyInfo, bodyErr := p.readBody(resp)
	if bodyErr != nil {
		return p.errorResult(target, opts, bodyErr, time.Since(start)), nil
	}

	httpRes := &HTTPResult{
		StatusCode:      resp.StatusCode,
		StatusText:      strings.TrimSpace(resp.Status),
		Proto:           resp.Proto,
		ContentLength:   resp.ContentLength,
		BodyBytesRead:   bodyInfo.total,
		BodyTruncated:   bodyInfo.truncated,
		Headers:         p.sanitizeResponseHeaders(resp.Header),
		RejectedHeaders: rejectedHeaders,
		RedirectCount:   len(rev.hops),
		Hops:            rev.hops,
	}
	if bodyInfo.total > 0 {
		httpRes.BodySHA256 = bodyInfo.sha256
	}
	if opts.ReturnBodySnippet && bodyInfo.snippet != "" {
		httpRes.BodySnippet = SanitizeSnippet(bodyInfo.snippet)
	}
	if opts.IncludeTLSInfo && resp.TLS != nil {
		if info, terr := extractTLS(resp.TLS); terr == nil {
			httpRes.TLS = info
		}
	}

	res := &Result{
		Success: true,
		Probe:   "http_probe",
		Target: Target{
			Requested:  opts.URL,
			Hostname:   target.Hostname,
			ResolvedIP: target.IP.String(),
			Port:       target.Port,
			Scheme:     target.Scheme,
		},
		HTTP: httpRes,
	}
	res.DurationMs = ms(time.Since(start))
	res.Timings = Timings{
		DNSMs:     ms(target.DNSTime),
		ConnectMs: ms(rev.connectDur),
		TLSMs:     ms(rev.tlsDur),
		ProcessMs: ms(rev.firstByteDur),
		TotalMs:   res.DurationMs,
	}
	return res, nil
}

func (p *HTTPProber) newClient(dialer *security.SafeDialer, rev *redirectRevalidator, target *security.SafeTarget) *http.Client {
	tr := &http.Transport{
		DialContext:           rev.dialContext,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   p.timeout,
		ResponseHeaderTimeout: p.timeout,
	}
	if p.cfg.RootCAs != nil {
		tr.TLSClientConfig = &tls.Config{
			RootCAs:    p.cfg.RootCAs,
			ServerName: target.Hostname,
			MinVersion: tls.VersionTLS12,
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   p.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return rev.onRedirect(req, via)
		},
	}
}

// dialContext picks the SafeTarget for the current request. After a redirect
// the revalidator has stored a fresh SafeTarget; the dialer function uses
// whichever is current. The PinnedDialContext guarantees we only ever dial
// the validated IP.
func (r *redirectRevalidator) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	r.mu.Lock()
	target := r.cur
	r.mu.Unlock()
	if target == nil {
		return nil, errors.New("dial blocked: no authorized target")
	}
	return r.dialer.PinnedDialContext(target)(ctx, network, addr)
}

// applyHeaders validates and copies caller-supplied headers into the
// request. Returns the list of rejected entries with the reason so
// the caller can surface them in HTTPResult.RejectedHeaders. The
// function is defensive in depth: forbidden headers are silently
// dropped even when the operator's allow-list would have permitted
// them, and the rejection is recorded for transparency.
func (p *HTTPProber) applyHeaders(req *http.Request, headers map[string]string) []RejectedHeader {
	if req == nil || len(headers) == 0 {
		return nil
	}
	var rejected []RejectedHeader
	for k, v := range headers {
		lk := strings.ToLower(strings.TrimSpace(k))
		if forbiddenRequestHeaders[lk] {
			rejected = append(rejected, RejectedHeader{Name: k, Reason: "forbidden by policy"})
			continue
		}
		if !p.headerAllowed(lk) {
			rejected = append(rejected, RejectedHeader{Name: k, Reason: "not in allow-list"})
			continue
		}
		if strings.ContainsAny(k, ":\r\n\x00") || strings.ContainsAny(v, "\r\n\x00") {
			rejected = append(rejected, RejectedHeader{Name: k, Reason: "invalid characters (CRLF/NUL)"})
			continue
		}
		if len(v) > 1024 {
			rejected = append(rejected, RejectedHeader{Name: k, Reason: "value exceeds 1024 bytes"})
			continue
		}
		req.Header.Set(k, v)
	}
	return rejected
}

func (p *HTTPProber) sanitizeResponseHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		val := vs[0]
		if len(val) > 512 {
			val = val[:512] + "..."
		}
		out[k] = SanitizeSnippet(val)
	}
	return out
}

type bodyInfo struct {
	total     int64
	truncated bool
	snippet   string
	sha256    string
}

func (p *HTTPProber) readBody(resp *http.Response) (bodyInfo, error) {
	limited := io.LimitReader(resp.Body, p.cfg.MaxBodyBytes+1)
	hasher := sha256.New()
	snipBuf := &bytes.Buffer{}
	snipCap := int64(p.cfg.MaxReturnedBytes)

	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, rerr := limited.Read(buf)
		if n > 0 {
			total += int64(n)
			hasher.Write(buf[:n])
			remaining := snipCap - int64(snipBuf.Len())
			if remaining > 0 {
				toWrite := int64(n)
				if toWrite > remaining {
					toWrite = remaining
				}
				snipBuf.Write(buf[:toWrite])
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return bodyInfo{}, rerr
		}
	}
	truncated := total > p.cfg.MaxBodyBytes
	if truncated {
		total = p.cfg.MaxBodyBytes
	}
	return bodyInfo{
		total:     total,
		truncated: truncated,
		snippet:   snipBuf.String(),
		sha256:    hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

func (p *HTTPProber) errorResult(target *security.SafeTarget, opts HTTPOptions, err error, dur time.Duration) *Result {
	r := &Result{
		Success:    false,
		Probe:      "http_probe",
		Target:     httpTargetDescribe(target, opts),
		Error:      sanitizeNetErr(err),
		ErrorClass: classifyHTTPError(err),
	}
	r.DurationMs = ms(dur)
	r.Timings.TotalMs = r.DurationMs
	r.Timings.DNSMs = ms(target.DNSTime)
	return r
}

func (p *HTTPProber) redirectBlockedResult(target *security.SafeTarget, opts HTTPOptions, rerr *ErrRedirectBlocked, dur time.Duration) *Result {
	r := &Result{
		Success:    false,
		Probe:      "http_probe",
		Target:     httpTargetDescribe(target, opts),
		Error:      fmt.Sprintf("redirect blocked: %s", rerr.Reason),
		ErrorClass: "policy",
		HTTP: &HTTPResult{
			RedirectBlocked: &BlockedRedirect{
				Target:     rerr.Target,
				Category:   rerr.Category,
				Reason:     rerr.Reason,
				StatusCode: rerr.Status,
			},
		},
	}
	r.DurationMs = ms(dur)
	r.Timings.TotalMs = r.DurationMs
	r.Timings.DNSMs = ms(target.DNSTime)
	return r
}

func httpTargetDescribe(target *security.SafeTarget, opts HTTPOptions) Target {
	return Target{
		Requested:  opts.URL,
		Hostname:   target.Hostname,
		ResolvedIP: target.IP.String(),
		Port:       target.Port,
		Scheme:     target.Scheme,
	}
}

// redirectRevalidator is shared between the http.Client and the prober.
// It owns the *current* SafeTarget: when a redirect is allowed, a fresh
// target is computed by the guard and stored as `cur` so the dialer can
// pick it up on the next connection.
type redirectRevalidator struct {
	guard *security.Guard
	max   int
	allow bool
	ctx   context.Context

	mu     sync.Mutex
	cur    *security.SafeTarget
	dialer *security.SafeDialer

	hops         []HopResult
	connectDur   time.Duration
	tlsDur       time.Duration
	firstByteDur time.Duration
}

func (r *redirectRevalidator) onRedirect(req *http.Request, via []*http.Request) error {
	if !r.allow || r.guard == nil {
		return http.ErrUseLastResponse
	}
	r.mu.Lock()
	if len(r.hops) >= r.max {
		r.mu.Unlock()
		return errors.New("max redirects exceeded")
	}
	r.mu.Unlock()

	last := via[len(via)-1]
	status := 0
	if last.Response != nil {
		status = last.Response.StatusCode
	}
	if status == 0 {
		// Some Go HTTP client code paths do not propagate Response on the
		// last hop. Fall back to the Location status class, defaulting to
		// 3xx which is the only class where CheckRedirect runs anyway.
		status = http.StatusFound
	}

	// Refuse HTTPS → HTTP downgrades (PLAN §5.6). A redirect from an
	// HTTPS endpoint to a plain HTTP one would leak any state that the
	// client appended to the second request (cookies, path-bound
	// tokens) over an unencrypted channel. This check is independent
	// of the Guard pipeline and must run before it.
	if last.URL.Scheme == "https" && req.URL.Scheme == "http" {
		return &ErrRedirectBlocked{
			Target:   req.URL.String(),
			Category: "downgrade",
			Reason:   "redirect blocked: HTTPS to HTTP downgrade",
			Status:   status,
		}
	}

	scheme := "http"
	if req.URL.Scheme == "https" {
		scheme = "https"
	}
	port := uint16(0)
	if p, err := strconv.ParseUint(req.URL.Port(), 10, 16); err == nil {
		port = uint16(p)
	} else {
		switch scheme {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	}

	target, err := r.guard.Authorize(req.Context(), security.Request{
		Tool:    "http_probe",
		Scheme:  scheme,
		Host:    req.URL.Hostname(),
		Port:    port,
		Path:    req.URL.Path,
		Purpose: security.PurposeProbe,
	})
	if err != nil {
		var de *security.DenyError
		cat := "denied"
		reason := err.Error()
		if errors.As(err, &de) {
			cat = string(de.Category)
			reason = de.Reason
		}
		return &ErrRedirectBlocked{
			Target:   req.URL.String(),
			Category: cat,
			Reason:   reason,
			Status:   status,
		}
	}

	r.mu.Lock()
	if r.cur != nil {
		r.cur.Release()
	}
	r.cur = target
	r.hops = append(r.hops, HopResult{
		URL:        req.URL.String(),
		StatusCode: status,
		ResolvedIP: target.IP.String(),
	})
	r.mu.Unlock()
	return nil
}

func (r *redirectRevalidator) recordTLS(d time.Duration) {
	r.mu.Lock()
	r.tlsDur = d
	r.mu.Unlock()
}

func (r *redirectRevalidator) recordConnect(d time.Duration) {
	r.mu.Lock()
	r.connectDur = d
	r.mu.Unlock()
}

func (r *redirectRevalidator) recordFirstByte(d time.Duration) {
	r.mu.Lock()
	r.firstByteDur = d
	r.mu.Unlock()
}

func extractTLS(state *tls.ConnectionState) (*TLSPassiveInfo, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, errors.New("no peer certificates")
	}
	leaf := state.PeerCertificates[0]
	now := time.Now()
	days := leaf.NotAfter.Sub(now).Hours() / 24
	return &TLSPassiveInfo{
		Version:           tlsVersionName(state.Version),
		CipherSuite:       tls.CipherSuiteName(state.CipherSuite),
		NegotiatedALPN:    state.NegotiatedProtocol,
		FingerprintSHA256: fingerprintSHA256(leaf.Raw),
		DaysUntilExpiry:   days,
		NotBefore:         leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          leaf.NotAfter.UTC().Format(time.RFC3339),
		Subject:           leaf.Subject.String(),
		Issuer:            leaf.Issuer.String(),
		SANCount:          len(leaf.DNSNames) + len(leaf.IPAddresses),
	}, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("unknown(0x%x)", v)
}

func fingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// classifyHTTPError maps a transport-level error to a stable category.
func classifyHTTPError(err error) string {
	if err == nil {
		return ""
	}
	if isTimeout(err) {
		return "timeout"
	}
	var rerr *ErrRedirectBlocked
	if errors.As(err, &rerr) {
		return "policy"
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return "network"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "tls"):
		return "tls"
	case strings.Contains(s, "connection refused"):
		return "connect_refused"
	case strings.Contains(s, "no route to host"):
		return "unreachable"
	case strings.Contains(s, "dial blocked"):
		return "policy"
	case strings.Contains(s, "redirect to"):
		return "policy"
	}
	return "network"
}
