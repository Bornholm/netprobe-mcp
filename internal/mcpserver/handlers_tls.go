package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	b += summarizeTLSEvidence(r)
	return b
}

// Finding IDs that justify surfacing extra chain/crypto/identity evidence
// in the agent-readable summary. The summary is the first thing the model
// reads; the PLAN (§9.5) requires it to carry every decisive fact, so the
// agent does not need to round-trip through the structured payload to
// identify the missing intermediate or the SAN that triggered the wildcard
// finding. Limited to chain, identity and crypto — the categories where
// the leaf fields (Issuer, AIA, SAN, PublicKey) are themselves the answer.
var tlsEvidenceTriggers = map[string]struct{}{
	// chain
	"TLS_CHAIN_INCOMPLETE":           {},
	"TLS_CHAIN_MISSING_INTERMEDIATE": {},
	"TLS_CHAIN_MISORDERED":           {},
	"TLS_CHAIN_ROOT_INCLUDED":        {},
	"TLS_CHAIN_EXTRANEOUS_CERT":      {},
	"TLS_SELF_SIGNED":                {},
	"TLS_UNTRUSTED_ROOT":             {},
	// identity
	"TLS_HOSTNAME_MISMATCH":  {},
	"TLS_NO_SAN":             {},
	"TLS_CN_ONLY_IDENTITY":   {},
	"TLS_WILDCARD_TOO_BROAD": {},
	// crypto
	"TLS_WEAK_SIGNATURE_SHA1":  {},
	"TLS_WEAK_RSA_KEY":         {},
	"TLS_WEAK_EC_CURVE":        {},
	"TLS_SUBOPTIMAL_RSA_KEY":   {},
	"TLS_CA_CERT_USED_AS_LEAF": {},
}

// hasTrigger reports whether at least one finding ID in the report is
// in the trigger set. Avoids polluting every summary with chain/leaf
// details when the certificate is healthy.
func hasTrigger(findings []tlsdiag.Finding) bool {
	for _, f := range findings {
		if _, ok := tlsEvidenceTriggers[f.ID]; ok {
			return true
		}
	}
	return false
}

// summarizeTLSEvidence appends agent-readable chain/identity/crypto
// evidence derived from the leaf and chain reports. Only emitted when a
// finding in the trigger set is present; the formatted strings are short
// and stable so they can be referenced from the structured payload.
//
// The fields mirror what an operator would read from `openssl x509 -text
// -noout` for the leaf, but bounded to what the rule findings need.
func summarizeTLSEvidence(r *tlsdiag.Report) string {
	if r == nil || !hasTrigger(r.Findings) {
		return ""
	}

	var chainParts []string
	chainParts = append(chainParts, fmt.Sprintf("presented=%d", r.Chain.Length))
	if r.Chain.Length > 0 {
		chainParts = append(chainParts, fmt.Sprintf("complete=%t", r.Chain.Complete))
		chainParts = append(chainParts, fmt.Sprintf("ordered=%t", r.Chain.Ordered))
	}
	if r.Chain.MissingIntermediate && len(r.Leaf.IssuingCertURLs) > 0 {
		chainParts = append(chainParts, fmt.Sprintf("aia_ca_issuer=%s", r.Leaf.IssuingCertURLs[0]))
	}
	chainLine := "\n [chain] " + strings.Join(chainParts, " ")

	var leafParts []string
	if r.Leaf.PublicKeyAlgorithm != "" {
		bits := r.Leaf.PublicKeyBits
		if bits > 0 {
			leafParts = append(leafParts, fmt.Sprintf("key=%s-%d", r.Leaf.PublicKeyAlgorithm, bits))
		} else {
			leafParts = append(leafParts, "key="+r.Leaf.PublicKeyAlgorithm)
		}
	}
	if r.Leaf.SignatureAlgorithm != "" {
		leafParts = append(leafParts, "sig="+r.Leaf.SignatureAlgorithm)
	}
	if wildcards := wildcardSANs(r.Leaf.DNSNames); len(wildcards) > 0 {
		leafParts = append(leafParts, "san_wildcards=["+strings.Join(wildcards, ",")+"]")
	}
	if r.Leaf.Subject != "" {
		leafParts = append(leafParts, fmt.Sprintf("subject=%q", r.Leaf.Subject))
	}
	if r.Chain.MatchedName != "" {
		leafParts = append(leafParts, fmt.Sprintf("matched=%q", r.Chain.MatchedName))
	}
	leafLine := ""
	if len(leafParts) > 0 {
		leafLine = "\n [leaf]  " + strings.Join(leafParts, " ")
	}

	return chainLine + leafLine
}

// wildcardSANs returns the DNS names that contain a leading wildcard,
// sorted for stable output.
func wildcardSANs(names []string) []string {
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, "*.") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
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
