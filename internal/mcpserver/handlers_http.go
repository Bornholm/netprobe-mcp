package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *Server) registerHTTPProbe() error {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:  "http_probe",
		Title: "Probe an HTTP(S) endpoint",
		Description: "Perform a single HTTP(S) request against an allow-listed target. " +
			"Reports status, timing breakdown (connect, TLS, TTFB, total), " +
			"response headers, an optional sanitized body snippet, and TLS " +
			"passive information. Bodies and most request headers are " +
			"restricted; redirects are re-authorized by the Guard pipeline. " +
			"No application-level payload is sent.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			IdempotentHint:  false,
			OpenWorldHint:   boolPtr(true),
		},
	}, s.handleHTTPProbe)
	return nil
}

// HTTPProbeIn is the agent-facing input for http_probe.
type HTTPProbeIn = probe.HTTPOptions

// HTTPProbeOut mirrors probe.Result.
type HTTPProbeOut = probe.Result

func (s *Server) handleHTTPProbe(ctx context.Context, req *mcp.CallToolRequest, in HTTPProbeIn) (*mcp.CallToolResult, HTTPProbeOut, error) {
	sessionID := sessionIDFromCtx(ctx, req)
	start := time.Now()

	// 1. Validate request parameters (parser-level errors).
	if err := s.httpProber.Prober.Validate(&in); err != nil {
		ev := &audit.Event{
			SessionID:  sessionID,
			Tool:       "http_probe",
			Outcome:    audit.OutcomeDenied,
			Decision:   "denied",
			DenyReason: err.Error(),
		}
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "http_probe REFUSED: " + err.Error(),
			}},
		}
		denied := &probe.Result{
			Probe:   "http_probe",
			Success: false,
			Error:   err.Error(),
		}
		return result, *denied, MarkDenied(ev)
	}

	// 2. Parse the URL to derive host/port/scheme for the guard.
	u, err := url.Parse(in.URL)
	if err != nil {
		// already caught by Validate above, but be defensive.
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "http_probe: url is malformed"}},
		}
		denied := &probe.Result{Probe: "http_probe", Success: false, Error: "url malformed"}
		return result, *denied, MarkDenied(&audit.Event{
			SessionID: sessionID, Tool: "http_probe", Decision: "denied", Outcome: audit.OutcomeDenied,
		})
	}
	port := defaultPort(u)
	if explicit, perr := parsePortString(u.Port()); perr == nil && u.Port() != "" {
		port = explicit
	}

	// 3. Authorize the initial URL.
	method := in.Method
	if method == "" {
		method = http.MethodGet
	}
	target, err := s.guard.Authorize(ctx, security.Request{
		Tool:      "http_probe",
		SessionID: sessionID,
		Scheme:    u.Scheme,
		Host:      u.Hostname(),
		Port:      port,
		Path:      u.Path,
		Method:    method,
		Purpose:   security.PurposeProbe,
	})
	if err != nil {
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "http_probe",
			Decision:        "denied",
			Outcome:         audit.OutcomeDenied,
			DenyReason:      security.PublicReason(err),
			RequestedTarget: in.URL,
		}
		s.recordDenial(ev, err)
		s.metrics.DenialsTotal.WithLabelValues("http_probe", string(denyCategory(err))).Inc()
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "http_probe REFUSED by policy: " + security.PublicReason(err),
			}},
		}
		denied := &probe.Result{
			Probe:   "http_probe",
			Success: false,
			Error:   security.PublicReason(err),
			Target: probe.Target{
				Requested: in.URL,
				Hostname:  u.Hostname(),
				Port:      port,
				Scheme:    u.Scheme,
			},
		}
		return result, *denied, MarkDenied(ev)
	}

	// 4. Decide whether to follow redirects.
	allowRedirect := s.httpProber.AllowRedirect
	if in.FollowRedirects != nil {
		allowRedirect = *in.FollowRedirects
	}

	// 5. Run the prober with its own per-tool context.
	probeCtx, cancel := context.WithTimeout(ctx, s.httpProber.DialTimeout)
	defer cancel()

	res, perr := s.httpProber.Run(probeCtx, target, s.dialer, in, allowRedirect, s.guard)
	target.Release()

	if perr != nil {
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "http_probe",
			Decision:        "allowed",
			Outcome:         audit.OutcomeInternal,
			DenyReason:      perr.Error(),
			RequestedTarget: in.URL,
		}
		s.recordInternal(req, sessionID, "http_probe", in.URL, perr)
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "http_probe internal error: " + probe.SanitizeNetErr(perr),
			}},
		}
		failed := &probe.Result{
			Probe:   "http_probe",
			Success: false,
			Error:   probe.SanitizeNetErr(perr),
		}
		return result, *failed, MarkInternal(ev)
	}

	// 6. Build the agent-facing text + structured result.
	dur := time.Since(start)
	if res != nil {
		res.DurationMs = float64(dur.Microseconds()) / 1000.0
	}

	outcome := audit.OutcomeSuccess
	if !res.Success {
		outcome = audit.OutcomeProbeFailure
	}
	auditEvent := &audit.Event{
		SessionID:       sessionID,
		Tool:            "http_probe",
		Decision:        "allowed",
		Outcome:         outcome,
		RequestedTarget: in.URL,
		ResolvedAddr:    res.Target.ResolvedIP,
		ResolvedPort:    res.Target.Port,
		DurationMs:      res.DurationMs,
	}
	if s.audit != nil {
		s.audit.Emit(auditEvent)
	}
	s.metrics.ProbesTotal.WithLabelValues("http_probe", outcome).Inc()
	s.metrics.ProbeDurationSecs.WithLabelValues("http_probe").Observe(res.DurationMs / 1000.0)

	if res == nil {
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "http_probe internal error: nil result"}},
		}
		return result, probe.Result{Probe: "http_probe", Success: false, Error: "nil result"}, errors.New("nil result")
	}

	text := summarizeHTTP(res)
	result := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
	return result, *res, nil
}

func defaultPort(u *url.URL) uint16 {
	switch u.Scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

// parsePortString parses a TCP port (1-65535) or returns 0 on empty.
func parsePortString(s string) (uint16, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not numeric: %q", s)
		}
		v = v*10 + uint64(c-'0')
	}
	if v == 0 || v > 65535 {
		return 0, fmt.Errorf("port out of range: %d", v)
	}
	return uint16(v), nil
}

// summarizeHTTP produces a short, human-readable summary the agent reads
// before parsing the structured output. The body snippet — which is
// content served by the target — is wrapped in <untrusted_remote_content>
// markers so the model treats it as opaque data, never as instructions.
// See PLAN.md §7.2 and §13.5.
func summarizeHTTP(r *probe.Result) string {
	if r == nil {
		return "http_probe: no result"
	}
	if !r.Success {
		extra := ""
		if r.HTTP != nil && r.HTTP.RedirectBlocked != nil {
			extra = fmt.Sprintf("; redirect to %s blocked (%s)",
				r.HTTP.RedirectBlocked.Target, r.HTTP.RedirectBlocked.Category)
		}
		return fmt.Sprintf("http_probe FAILED %s (%s)%s - %s",
			r.Target.Hostname, r.ErrorClass, extra, r.Error)
	}
	b := fmt.Sprintf("http_probe OK %s -> %d %s in %.0fms",
		r.Target.Hostname, r.HTTP.StatusCode, r.HTTP.StatusText, r.DurationMs)
	if r.HTTP.RedirectCount > 0 {
		b += fmt.Sprintf("; %d redirect(s)", r.HTTP.RedirectCount)
	}
	if r.HTTP.TLS != nil {
		b += fmt.Sprintf("; TLS=%s/%s expires=%.0fd",
			r.HTTP.TLS.Version, r.HTTP.TLS.CipherSuite, r.HTTP.TLS.DaysUntilExpiry)
	}
	if r.HTTP.BodySnippet != "" {
		source := fmt.Sprintf("%s://%s", r.Target.Scheme, r.Target.Hostname)
		b += "\n" + probe.WrapUntrustedContent(r.HTTP.BodySnippet, source)
	}
	return b
}
