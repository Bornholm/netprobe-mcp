package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/probe/tlsdiag"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerTLSDiagnose wires the tls_diagnose tool into the MCP server.
func (s *Server) registerTLSDiagnose() error {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:  "tls_diagnose",
		Title: "Passive TLS diagnostic",
		Description: "Open a single TLS connection against an allow-listed host and report on the " +
			"presented certificate chain, leaf validity, cryptographic strength and any stapled " +
			"OCSP response. Active checks (protocol enumeration, SNI-vs-default comparison, " +
			"cipher suite probing, AIA fetch, direct OCSP query) are not performed in v1; " +
			"they are listed in checks_skipped.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			IdempotentHint:  false,
			OpenWorldHint:   boolPtr(true),
		},
	}, s.handleTLSDiagnose)
	return nil
}

// TLSDiagnoseIn is the agent-facing input for tls_diagnose. It maps
// directly onto tlsdiag.DiagnoseOptions so the JSON schema is owned
// by the analyser package.
type TLSDiagnoseIn = tlsdiag.DiagnoseOptions

// TLSDiagnoseOut is the agent-facing output for tls_diagnose.
type TLSDiagnoseOut = tlsdiag.Report

func (s *Server) handleTLSDiagnose(ctx context.Context, req *mcp.CallToolRequest, in TLSDiagnoseIn) (*mcp.CallToolResult, TLSDiagnoseOut, error) {
	sessionID := sessionIDFromCtx(ctx, req)
	start := time.Now()

	if in.Port == 0 {
		in.Port = 443
	}

	// 1. Validate the hostname syntactically.
	if in.Host == "" {
		ev := &audit.Event{
			SessionID:  sessionID,
			Tool:       "tls_diagnose",
			Decision:   "denied",
			Outcome:    audit.OutcomeDenied,
			DenyReason: "host is required",
		}
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "tls_diagnose REFUSED: host is required",
			}},
		}
		denied := &tlsdiag.Report{Target: tlsdiag.TargetInfo{Port: in.Port}, Verdict: "host is required"}
		return result, *denied, MarkDenied(ev)
	}

	// 2. Authorize through the Guard pipeline. This consumes one
	//    rate-limit slot per call (matching the design decision in
	//    PLAN.md §6.5).
	target, err := s.guard.Authorize(ctx, security.Request{
		Tool:      "tls_diagnose",
		SessionID: sessionID,
		Scheme:    "tls",
		Host:      in.Host,
		Port:      in.Port,
		Purpose:   security.PurposeProbe,
	})
	if err != nil {
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "tls_diagnose",
			Decision:        "denied",
			Outcome:         audit.OutcomeDenied,
			DenyReason:      security.PublicReason(err),
			RequestedTarget: in.Host,
		}
		s.recordDenial(ev, err)
		s.metrics.DenialsTotal.WithLabelValues("tls_diagnose", string(denyCategory(err))).Inc()
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "tls_diagnose REFUSED by policy: " + security.PublicReason(err),
			}},
		}
		denied := &tlsdiag.Report{
			Target:  tlsdiag.TargetInfo{Host: in.Host, Port: in.Port},
			Verdict: security.PublicReason(err),
		}
		return result, *denied, MarkDenied(ev)
	}

	// 3. Run the diagnostic. The analyser never returns an error for
	//    network conditions; handshake failures are reported as a
	//    partial Report rather than a tool error.
	rep, derr := s.tlsDiagnose.Analyzer.Diagnose(target, in)
	target.Release()

	if derr != nil {
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "tls_diagnose",
			Decision:        "allowed",
			Outcome:         audit.OutcomeInternal,
			DenyReason:      derr.Error(),
			RequestedTarget: in.Host,
		}
		s.recordInternal(req, sessionID, "tls_diagnose", in.Host, derr)
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "tls_diagnose internal error: " + sanitizeTLSDiagErr(derr),
			}},
		}
		failed := &tlsdiag.Report{
			Target:  tlsdiag.TargetInfo{Host: in.Host, Port: in.Port},
			Verdict: sanitizeTLSDiagErr(derr),
		}
		return result, *failed, MarkInternal(ev)
	}
	if rep == nil {
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "tls_diagnose internal error: nil result"}},
		}
		return result, tlsdiag.Report{Target: tlsdiag.TargetInfo{Host: in.Host, Port: in.Port}, Verdict: "nil result"}, errors.New("nil result")
	}

	// 4. Audit + metrics.
	rep.ScanDurationMs = float64(time.Since(start).Microseconds()) / 1000.0
	outcome := audit.OutcomeSuccess
	if !rep.Handshake.Succeeded || rep.Summary.Critical > 0 {
		outcome = audit.OutcomeProbeFailure
	}
	if s.audit != nil {
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "tls_diagnose",
			Decision:        "allowed",
			Outcome:         outcome,
			RequestedTarget: in.Host,
			ResolvedAddr:    rep.Target.Resolved,
			ResolvedPort:    rep.Target.Port,
			DurationMs:      rep.ScanDurationMs,
		}
		// Surface every secondary outbound request (AIA/OCSP) in the
		// audit log. These URLs come from the certificate presented
		// by the target — attacker-controlled — so post-incident
		// analysis depends on them being recorded.
		for _, o := range rep.OutboundRequests {
			ev.OutboundURLs = append(ev.OutboundURLs, audit.OutboundURLEvent{
				URL:       o.URL,
				Purpose:   o.Purpose,
				Outcome:   o.Outcome,
				BytesRead: o.BytesRead,
				Reason:    o.Reason,
			})
		}
		// Stable finding IDs make it possible to alert on a
		// specific class of issue without parsing the structured
		// payload. We cap at 32 IDs to keep the log entry bounded.
		maxIDs := 32
		for _, f := range rep.Findings {
			if maxIDs <= 0 {
				break
			}
			ev.Findings = append(ev.Findings, f.ID)
			maxIDs--
		}
		s.audit.Emit(ev)
	}
	s.metrics.ProbesTotal.WithLabelValues("tls_diagnose", outcome).Inc()
	s.metrics.ProbeDurationSecs.WithLabelValues("tls_diagnose").Observe(rep.ScanDurationMs / 1000.0)

	text := summarizeTLS(rep)
	result := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
	return result, *rep, nil
}

// summarizeTLS produces a short, agent-readable summary.
func summarizeTLS(r *tlsdiag.Report) string {
	if r == nil {
		return "tls_diagnose: no result"
	}
	b := fmt.Sprintf("tls_diagnose %s -> %s [grade %s, score %d] (findings: %d critical, %d high, %d medium, %d low, %d info)",
		r.Target.Host,
		r.Verdict,
		r.Grade,
		r.Score,
		r.Summary.Critical,
		r.Summary.High,
		r.Summary.Medium,
		r.Summary.Low,
		r.Summary.Info,
	)
	if r.Handshake.Succeeded {
		b += fmt.Sprintf(" [handshake: %s/%s]", r.Handshake.Version, r.Handshake.CipherSuite)
		if r.OCSP != nil && r.OCSP.Stapled {
			b += " [ocsp stapled]"
		}
	} else {
		b += fmt.Sprintf(" [handshake failed: %s]", r.Handshake.FailureReason)
	}
	if r.Protocols != nil {
		b += fmt.Sprintf(" [protocols: TLS1.2=%s TLS1.3=%s]", r.Protocols.TLS12, r.Protocols.TLS13)
	}
	if r.CipherSuites != nil {
		b += fmt.Sprintf(" [FS=%v]", r.CipherSuites.ForwardSecrecy)
	}
	if r.HSTS != nil {
		b += fmt.Sprintf(" [HSTS: max-age=%d redirect=%v]", r.HSTS.MaxAgeSeconds, r.HSTS.HTTPSRedirect)
	}
	if r.StartTLS != nil {
		b += fmt.Sprintf(" [STARTTLS %s: ok=%v]", r.StartTLS.Protocol, r.StartTLS.UpgradeSucceeded)
	}
	if len(r.Findings) > 0 {
		b += "\nTop findings:"
		limit := len(r.Findings)
		if limit > 3 {
			limit = 3
		}
		for _, f := range r.Findings[:limit] {
			b += fmt.Sprintf("\n  - %s (%s): %s", f.ID, f.Severity, f.Title)
		}
	}
	return b
}

// sanitizeTLSDiagErr is the error reducer used when the analyser
// itself returns an unexpected error (programmer mistake). Truncated
// to avoid leaking internals into the model context.
func sanitizeTLSDiagErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 240 {
		msg = msg[:240] + "…"
	}
	return msg
}
