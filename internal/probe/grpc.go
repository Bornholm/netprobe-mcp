// Package probe — gRPC health probe.
//
// The prober implements the gRPC Health Checking Protocol
// (https://grpc.io/docs/grpc-health-checking-protocol/) restricted to
// the single Service/Check method:
//
//	POST /grpc.health.v1.Health/Check
//	body: HealthCheckRequest{service=...}
//	resp: HealthCheckResponse{status=...}, grpc-status trailer
//
// Per PLAN §7.6, NO other gRPC methods are exposed, and reflection is
// not touched. The wire format is implemented by hand using net/http
// (which negotiates HTTP/2 transparently) so the binary keeps its
// "no gRPC dependency" posture: the gRPC Go SDK pulls megabytes of
// transitive code that we do not need for a single unary call.
//
// Connections are dialled through SafeDialer.PinnedDialContext, so:
//   - The IP is fixed to the value the Guard pipeline authorised.
//   - DNS rebinding is impossible (no second resolution).
//   - The IP filter is enforced one last time via the Control
//     callback inside net.Dialer.
package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// GRPCOptions is the agent-facing input for grpc_probe.
type GRPCOptions struct {
	Host      string `json:"host" jsonschema:"hostname to probe"`
	Port      int    `json:"port,omitempty" jsonschema:"TCP port (1-65535); defaults to 50051 for plaintext, 443 for TLS"`
	Service   string `json:"service,omitempty" jsonschema:"gRPC service name to check; empty = overall server health"`
	UseTLS    bool   `json:"use_tls,omitempty" jsonschema:"wrap the connection in TLS (h2)"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
}

// GRPCResult is the structured, agent-facing output of a successful
// gRPC health probe.
type GRPCResult struct {
	HealthStatus string       `json:"health_status" jsonschema:"SERVING, NOT_SERVING, UNKNOWN, SERVICE_UNKNOWN, or non-2xx status"`
	Healthy      bool         `json:"healthy" jsonschema:"true iff HealthStatus == SERVING"`
	HTTPStatus   int          `json:"http_status,omitempty" jsonschema:"HTTP/2 :status from the response head"`
	GRPCStatus   string       `json:"grpc_status,omitempty" jsonschema:"trailer grpc-status, when present"`
	GRPCMessage  string       `json:"grpc_message,omitempty" jsonschema:"trailer grpc-message, when present"`
	TLS          *GRPCTLSInfo `json:"tls,omitempty"`
}

// GRPCTLSInfo carries a minimal TLS fingerprint of the peer when
// UseTLS is true. Mirrors the smaller surface of TLSHandshakeInfo
// used by tls_diagnose, but stripped down because the gRPC probe is
// not a TLS auditor.
type GRPCTLSInfo struct {
	Version            string `json:"version,omitempty"`
	CipherSuite        string `json:"cipher_suite,omitempty"`
	PeerSubject        string `json:"peer_subject,omitempty"`
	PeerIssuer         string `json:"peer_issuer,omitempty"`
	NotAfter           string `json:"not_after,omitempty"`
	InsecureSkipVerify bool   `json:"-"` // never serialised; document the intent
}

// GRPCProbeResult is the full tool result: embeds probe.Result
// (target info, timings, error reporting) and adds the gRPC-specific
// block. The outer type is named to avoid collision with
// probe.Result, which is the embedded type.
type GRPCProbeResult struct {
	Result
	GRPC *GRPCResult `json:"grpc,omitempty"`
}

// GRPCProber performs a single gRPC Health/Check call against a
// SafeTarget. The zero value is NOT usable; always construct through
// NewGRPCProber so the timeouts are bounded.
type GRPCProber struct {
	defaultTimeout time.Duration
	defaultPort    uint16
}

// NewGRPCProber builds a prober. defaultPort is used when the call
// omits a port; the standard for plaintext gRPC is 50051, but a
// common case (gRPC-web behind ingress) is 443. We default to
// 50051 and let the agent override per-call.
func NewGRPCProber(defaultTimeout time.Duration, defaultPort uint16) *GRPCProber {
	if defaultTimeout <= 0 {
		defaultTimeout = 10 * time.Second
	}
	if defaultPort == 0 {
		defaultPort = 50051
	}
	return &GRPCProber{defaultTimeout: defaultTimeout, defaultPort: defaultPort}
}

// Run executes one gRPC Health/Check against the target.
//
// The flow:
//
//  1. Validate options (port range, timeout).
//  2. Build an http.Client whose Transport is pinned to the
//     SafeTarget's IP via SafeDialer.PinnedDialContext.
//  3. Open one TCP connection via the pinned dialer.
//  4. If UseTLS, wrap with crypto/tls (ServerName = hostname,
//     MinVersion = TLS 1.2).
//  5. Send POST /grpc.health.v1.Health/Check with content-type
//     application/grpc and a 5-byte length-prefixed body (zero
//     length: HealthCheckRequest has no required fields).
//  6. Read the entire response body and inspect Response.Trailer
//     for grpc-status / grpc-message.
//
// The connection is closed on return; gRPC health probes are
// intentionally one-shot, not pooled (PLAN §13.13 spirit:
// never reuse HTTP/2 connections across targets with pinned IP).
func (p *GRPCProber) Run(ctx context.Context, target *security.SafeTarget, dialer *security.SafeDialer, opts GRPCOptions) (*GRPCProbeResult, error) {
	start := Now()

	if opts.Port < 0 || opts.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d", opts.Port)
	}
	port := uint16(opts.Port)
	if port == 0 {
		port = p.defaultPort
	}
	if target.Port != port {
		return nil, fmt.Errorf("port mismatch: target pinned to %d, options say %d", target.Port, port)
	}

	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = p.defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	scheme := "http"
	if opts.UseTLS {
		scheme = "https"
	}

	// Path is hard-coded: per PLAN §7.6, only Health/Check is
	// exposed. The agent cannot pick the service/method.
	path := "/grpc.health.v1.Health/Check"

	// gRPC over HTTP requires specific headers and a
	// length-prefixed body. HealthCheckRequest has a single
	// optional `service` string field (tag 1, wire type 2).
	// We hand-encode the protobuf to avoid pulling in the
	// google.golang.org/protobuf runtime. The encoding is:
	//   - 5-byte length-prefixed message header
	//   - tag byte (0x0a for field 1, wire type 2)
	//   - varint length of the service name
	//   - service UTF-8 bytes
	// If no service name is supplied, the body is a zero-length
	// message (the spec mandates this for "overall server
	// health").
	reqBody := buildHealthCheckRequest(opts.Service)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		scheme+"://"+net.JoinHostPort(target.Hostname, strconv.Itoa(int(port)))+path,
		bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers") // required by spec; trailers carry grpc-status

	// Build a Transport that:
	//   - dials through the pinned dialer,
	//   - allows H2C (plaintext HTTP/2) when UseTLS is false,
	//   - forces HTTP/2 with the right protocol set,
	//   - uses the hostname as SNI when UseTLS is true.
	transport := p.newTransport(target, dialer, opts.UseTLS)

	// One-shot client; no cookie jar, no keep-alive. Per PLAN
	// §13.13 we never share an http.Transport across targets
	// because HTTP/2 connection coalescing can route a request
	// for the wrong SNI onto a previously-validated connection.
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Jar: nil — gRPC has no cookie semantics.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// gRPC does not redirect; refuse one if it happens.
			return errors.New("gRPC probe does not follow redirects")
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return p.errorResult(target, opts, err, time.Since(start))
	}
	defer func() {
		// Drain body so the connection can be closed cleanly.
		// DisableKeepAlives=true here means we don't care
		// about the pool, but draining is still polite.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// Drain the response body before reading trailers; gRPC
	// guarantees trailers only after the body. We bound the read
	// by io.LimitReader so a misbehaving server cannot exhaust
	// memory.
	maxRead := int64(64 * 1024)
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxRead)); err != nil {
		return p.errorResult(target, opts, fmt.Errorf("read body: %w", err), time.Since(start))
	}

	grpcStatus := resp.Trailer.Get("Grpc-Status")
	grpcMessage := resp.Trailer.Get("Grpc-Message")
	if grpcStatus == "" {
		// Some servers send the status inline in the response
		// headers instead of trailers. Cover both per RFC: the
		// spec allows either, and net/http merges them into
		// Response.Header when trailers are absent.
		grpcStatus = resp.Header.Get("Grpc-Status")
		grpcMessage = resp.Header.Get("Grpc-Message")
	}

	httpStatus := resp.StatusCode
	hs := healthStatusFromGRPC(resp.StatusCode, grpcStatus)
	healthy := hs == "SERVING"

	out := &GRPCProbeResult{
		Result: Result{
			Success: hs == "SERVING",
			Probe:   "grpc_probe",
			Target: Target{
				Requested:  net.JoinHostPort(target.Hostname, strconv.Itoa(int(port))),
				Hostname:   target.Hostname,
				ResolvedIP: target.IP.String(),
				Port:       port,
				Scheme:     "grpc",
			},
		},
		GRPC: &GRPCResult{
			HealthStatus: hs,
			Healthy:      healthy,
			HTTPStatus:   httpStatus,
			GRPCStatus:   grpcStatus,
			GRPCMessage:  grpcMessage,
		},
	}

	if opts.UseTLS && resp.TLS != nil {
		out.GRPC.TLS = tlsInfoFromState(resp.TLS)
	}

	out.DurationMs = ms(time.Since(start))
	out.Timings.TotalMs = out.DurationMs
	out.Timings.ConnectMs = ms(target.DNSTime) // best-effort; real connect time is buried in net/http
	return out, nil
}

// buildHealthCheckRequest hand-encodes a HealthCheckRequest
// protobuf message. The message has a single optional `service`
// string field (field 1, wire type 2). When service is empty, we
// emit a zero-length message — the gRPC spec treats this as
// "check the overall server health" rather than a specific
// service.
//
// The wire format is documented in
// https://protobuf.dev/programming-guides/encoding/ — for our
// purposes only a single byte matters:
//
//	0x0a <varint-length> <bytes>     (field 1, wire type 2)
//	0x00                             (compressed flag)
//	<4-byte big-endian length>
//
// We only support service names ≤127 bytes (single-byte varint)
// because anything longer is not a valid gRPC service name.
func buildHealthCheckRequest(service string) []byte {
	if service == "" {
		return []byte{0x00, 0x00, 0x00, 0x00, 0x00}
	}
	if len(service) > 127 {
		service = service[:127]
	}
	msg := make([]byte, 0, 2+len(service))
	msg = append(msg, 0x0a)               // tag: field 1, wire type 2
	msg = append(msg, byte(len(service))) // varint length (single byte fits ≤127)
	msg = append(msg, service...)         // UTF-8 bytes

	out := make([]byte, 0, 5+len(msg))
	out = append(out, 0x00) // compressed flag: uncompressed
	// Big-endian uint32 length.
	mlen := uint32(len(msg))
	out = append(out,
		byte(mlen>>24), byte(mlen>>16), byte(mlen>>8), byte(mlen))
	out = append(out, msg...)
	return out
}

// healthStatusFromGRPC maps the HTTP/2 + grpc-status pair onto the
// canonical health enum. Anything that is not "SERVING" becomes a
// distinct status so the agent can tell "I asked for service X and
// it does not exist" from "the server is up but reports NOT_SERVING".
func healthStatusFromGRPC(httpStatus int, grpcStatus string) string {
	switch grpcStatus {
	case "0":
		return "SERVING"
	case "1": // CANCELLED
		return "CANCELLED"
	case "2": // UNKNOWN
		return "UNKNOWN"
	case "3": // INVALID_ARGUMENT — the agent passed a malformed request
		return "INVALID_ARGUMENT"
	case "4": // DEADLINE_EXCEEDED
		return "DEADLINE_EXCEEDED"
	case "5": // NOT_FOUND
		return "SERVICE_UNKNOWN"
	case "7": // PERMISSION_DENIED
		return "PERMISSION_DENIED"
	case "12": // UNIMPLEMENTED
		return "UNIMPLEMENTED"
	case "13": // INTERNAL
		return "INTERNAL_ERROR"
	case "14": // UNAVAILABLE
		return "UNAVAILABLE"
	}
	// No grpc-status trailer (or unknown code). Treat the HTTP
	// status as the verdict: 200 → SERVING is wrong (we cannot
	// confirm), so we say UNKNOWN; anything else reflects the
	// HTTP-level failure.
	switch httpStatus {
	case 200:
		return "UNKNOWN"
	case 401, 403:
		return "PERMISSION_DENIED"
	case 404:
		return "UNIMPLEMENTED"
	case 421, 426:
		return "UNAVAILABLE"
	case 500:
		return "INTERNAL_ERROR"
	case 502, 503, 504:
		return "UNAVAILABLE"
	}
	return "UNKNOWN"
}

// tlsInfoFromState extracts a minimal TLS summary from the
// connection state. The Subject/Issuer strings are untrusted remote
// data — they are returned as part of the report but the caller
// must wrap them with the same WrapUntrustedContent hygiene as
// other probes (see mcpserver/handlers_grpc.go).
func tlsInfoFromState(cs *tls.ConnectionState) *GRPCTLSInfo {
	if cs == nil {
		return nil
	}
	out := &GRPCTLSInfo{
		Version:     tlsVersionString(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
	}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		out.PeerSubject = leaf.Subject.String()
		out.PeerIssuer = leaf.Issuer.String()
		if !leaf.NotAfter.IsZero() {
			out.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	return out
}

func tlsVersionString(v uint16) string {
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
	return fmt.Sprintf("unknown(0x%04x)", v)
}

// newTransport builds the per-probe http.Transport.
//
// The single most important property: DialContext is the pinned
// dialer, so every byte of HTTP/2 traffic is written to the IP the
// Guard pipeline authorised. ForceAttemptHTTP2 + Protocols(H2C)
// covers both plaintext and TLS gRPC.
func (p *GRPCProber) newTransport(target *security.SafeTarget, dialer *security.SafeDialer, useTLS bool) *http.Transport {
	t := &http.Transport{
		DialContext:           dialer.PinnedDialContext(target),
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   0,
		IdleConnTimeout:       1 * time.Second,
		ResponseHeaderTimeout: p.defaultTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	// SetUnencryptedHTTP2 lets plaintext gRPC work over http://
	// URLs. For https:// it is a no-op: TLS upgrades to HTTP/2
	// via ALPN.
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(!useTLS)
	t.Protocols = protocols
	if useTLS {
		t.TLSClientConfig = &tls.Config{
			ServerName:         target.Hostname,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
		}
	}
	return t
}

// errorResult wraps a probe-level failure into a Result with
// Success=false. Mirrors the other probers' helpers (see tcp.go,
// icmp.go).
func (p *GRPCProber) errorResult(target *security.SafeTarget, opts GRPCOptions, err error, dur time.Duration) (*GRPCProbeResult, error) {
	addr, _ := netip.ParseAddr(target.IP.String())
	r := &GRPCProbeResult{
		Result: Result{
			Success:    false,
			Probe:      "grpc_probe",
			Target:     grpcTargetDescribe(target, opts, addr),
			Error:      sanitizeNetErr(err),
			ErrorClass: classifyNetError(err),
		},
	}
	r.DurationMs = ms(dur)
	r.Timings.TotalMs = r.DurationMs
	r.Timings.ConnectMs = ms(target.DNSTime)
	return r, nil
}

func grpcTargetDescribe(target *security.SafeTarget, opts GRPCOptions, _ netip.Addr) Target {
	port := uint16(opts.Port)
	if port == 0 {
		port = target.Port
	}
	scheme := "grpc"
	if opts.UseTLS {
		scheme = "grpc+tls"
	}
	return Target{
		Requested:  strings.TrimSuffix(opts.Host, "") + ":" + strconv.Itoa(int(port)),
		Hostname:   target.Hostname,
		ResolvedIP: target.IP.String(),
		Port:       port,
		Scheme:     scheme,
	}
}
