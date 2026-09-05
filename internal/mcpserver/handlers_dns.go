package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerDNSProbe wires the dns_probe tool into the MCP server.
func (s *Server) registerDNSProbe() error {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:  "dns_probe",
		Title: "Probe a DNS server",
		Description: "Issue a single DNS query against an allow-listed DNS server, optionally against " +
			"an allow-listed QNAME. Reports rcode, answers, flags, timing and optional assertions. " +
			"Servers and QNAMEs are validated against the Guard allow-list before any network I/O; " +
			"long QNAMEs, high-entropy labels, and unknown query types are rejected.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			IdempotentHint:  false,
			OpenWorldHint:   boolPtr(true),
		},
	}, s.handleDNSProbe)
	return nil
}

// DNSProbeIn is the agent-facing input for dns_probe.
type DNSProbeIn = probe.DNSOptions

// DNSProbeOut mirrors probe.Result.
type DNSProbeOut = probe.Result

func (s *Server) handleDNSProbe(ctx context.Context, req *mcp.CallToolRequest, in DNSProbeIn) (*mcp.CallToolResult, DNSProbeOut, error) {
	sessionID := sessionIDFromCtx(ctx, req)
	start := time.Now()

	// 1. Default the protocol.
	if in.Protocol == "" {
		in.Protocol = "udp"
	}

	// 2. Parser-level validation.
	if err := s.dnsProber.Prober.Validate(&in); err != nil {
		ev := &audit.Event{
			SessionID:  sessionID,
			Tool:       "dns_probe",
			Decision:   "denied",
			Outcome:    audit.OutcomeDenied,
			DenyReason: err.Error(),
		}
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "dns_probe REFUSED: " + err.Error(),
			}},
		}
		denied := &probe.Result{Probe: "dns_probe", Success: false, Error: err.Error()}
		return result, *denied, MarkDenied(ev)
	}

	// 3. Authorize the DNS server itself.
	if in.Server == "" {
		ev := &audit.Event{
			SessionID:  sessionID,
			Tool:       "dns_probe",
			Decision:   "denied",
			Outcome:    audit.OutcomeDenied,
			DenyReason: "server is required",
		}
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "dns_probe REFUSED: server is required",
			}},
		}
		denied := &probe.Result{Probe: "dns_probe", Success: false, Error: "server is required"}
		return result, *denied, MarkDenied(ev)
	}
	serverHost, serverPort, splitErr := splitHostPort(in.Server, probe.PortForProtocol(in.Protocol))
	if splitErr != nil {
		ev := &audit.Event{
			SessionID:  sessionID,
			Tool:       "dns_probe",
			Decision:   "denied",
			Outcome:    audit.OutcomeDenied,
			DenyReason: splitErr.Error(),
		}
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "dns_probe REFUSED: " + splitErr.Error(),
			}},
		}
		denied := &probe.Result{Probe: "dns_probe", Success: false, Error: splitErr.Error()}
		return result, *denied, MarkDenied(ev)
	}
	server, err := s.guard.Authorize(ctx, security.Request{
		Tool:      "dns_probe",
		SessionID: sessionID,
		Scheme:    probe.SchemeForProtocol(in.Protocol),
		Host:      serverHost,
		Port:      serverPort,
		Purpose:   security.PurposeProbe,
	})
	if err != nil {
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "dns_probe",
			Decision:        "denied",
			Outcome:         audit.OutcomeDenied,
			DenyReason:      security.PublicReason(err),
			RequestedTarget: in.Server,
		}
		s.recordDenial(ev, err)
		s.metrics.DenialsTotal.WithLabelValues("dns_probe", string(denyCategory(err))).Inc()
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "dns_probe REFUSED by policy: " + security.PublicReason(err),
			}},
		}
		denied := &probe.Result{
			Probe:   "dns_probe",
			Success: false,
			Error:   security.PublicReason(err),
		}
		return result, *denied, MarkDenied(ev)
	}

	// 4. Validate the QNAME against the allow-list (cheap pre-check).
	//    PTR queries legitimately take IP literals as names — skip the
	//    allow-list pre-check for those.
	//
	//    CheckQueryName, not CheckHostname: a query name is not a host
	//    name, and the underscored labels of RFC 8552 (_dmarc, _domainkey,
	//    _tcp) are the very records this tool is asked about.
	if !isPTRQuery(in) {
		if qerr := s.guard.CheckQueryName(ctx, in.Name, "dns_probe"); qerr != nil {
			server.Release()
			ev := &audit.Event{
				SessionID:       sessionID,
				Tool:            "dns_probe",
				Decision:        "denied",
				Outcome:         audit.OutcomeDenied,
				DenyReason:      "qname: " + security.PublicReason(qerr),
				RequestedTarget: in.Name,
			}
			s.recordDenial(ev, qerr)
			s.metrics.DenialsTotal.WithLabelValues("dns_probe", "qname").Inc()
			result := &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{
					Text: "dns_probe REFUSED by policy (qname): " + security.PublicReason(qerr),
				}},
			}
			denied := &probe.Result{
				Probe:   "dns_probe",
				Success: false,
				Error:   "qname: " + security.PublicReason(qerr),
			}
			return result, *denied, MarkDenied(ev)
		}
	}

	// 5. Run the probe.
	probeCtx, cancel := context.WithTimeout(ctx, s.dnsProber.DialTimeout)
	defer cancel()

	res, perr := s.dnsProber.Run(probeCtx, server, in)
	server.Release()

	if perr != nil {
		ev := &audit.Event{
			SessionID:       sessionID,
			Tool:            "dns_probe",
			Decision:        "allowed",
			Outcome:         audit.OutcomeInternal,
			DenyReason:      perr.Error(),
			RequestedTarget: in.Name,
		}
		s.recordInternal(req, sessionID, "dns_probe", in.Name, perr)
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "dns_probe internal error: " + probe.SanitizeNetErr(perr),
			}},
		}
		failed := &probe.Result{
			Probe:   "dns_probe",
			Success: false,
			Error:   probe.SanitizeNetErr(perr),
		}
		return result, *failed, MarkInternal(ev)
	}

	// 6. Audit + metrics.
	if res == nil {
		result := &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "dns_probe internal error: nil result"}},
		}
		return result, probe.Result{Probe: "dns_probe", Success: false, Error: "nil result"}, errors.New("nil result")
	}
	res.DurationMs = float64(time.Since(start).Microseconds()) / 1000.0

	outcome := audit.OutcomeSuccess
	if !res.Success {
		outcome = audit.OutcomeProbeFailure
	}
	if s.audit != nil {
		s.audit.Emit(&audit.Event{
			SessionID:       sessionID,
			Tool:            "dns_probe",
			Decision:        "allowed",
			Outcome:         outcome,
			RequestedTarget: in.Name,
			ResolvedAddr:    res.Target.ResolvedIP,
			ResolvedPort:    res.Target.Port,
			DurationMs:      res.DurationMs,
		})
	}
	s.metrics.ProbesTotal.WithLabelValues("dns_probe", outcome).Inc()
	s.metrics.ProbeDurationSecs.WithLabelValues("dns_probe").Observe(res.DurationMs / 1000.0)

	text := summarizeDNS(res)
	result := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
	return result, *res, nil
}

// summarizeDNS produces a short, agent-readable summary.
func summarizeDNS(r *probe.Result) string {
	if r == nil {
		return "dns_probe: no result"
	}
	if r.DNS == nil {
		return fmt.Sprintf("dns_probe FAILED %s - %s", r.Target.Hostname, r.Error)
	}
	answers := len(r.DNS.Answers)
	b := fmt.Sprintf("dns_probe %s -> %s (%d answers) in %.0fms via %s",
		r.Target.Hostname, r.DNS.Rcode, answers, r.DurationMs, r.DNS.ServerUsed)
	if r.DNS.Truncated {
		b += " [truncated]"
	}
	if len(r.DNS.Checks) > 0 {
		var failed int
		for _, c := range r.DNS.Checks {
			if !c.Passed {
				failed++
			}
		}
		if failed > 0 {
			b += fmt.Sprintf(" [checks failed: %d/%d]", failed, len(r.DNS.Checks))
		}
	}
	return b
}

// isPTRQuery returns true when the probe is a reverse lookup; the name is
// then an IP literal (IPv4 or IPv6) and must NOT be validated as a hostname.
func isPTRQuery(opts DNSProbeIn) bool {
	return strings.EqualFold(opts.QueryType, "PTR")
}

// splitHostPort parses an "host" or "host:port" string. When no port is
// provided, the supplied default is used. IPv6 literals must be wrapped in
// brackets (e.g. "[::1]:53").
func splitHostPort(s string, defaultPort uint16) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		// Not in host:port form — treat the whole string as host.
		host = s
		portStr = ""
	}
	if portStr == "" {
		return host, defaultPort, nil
	}
	var port uint64
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return "", 0, fmt.Errorf("invalid port %q", portStr)
		}
		port = port*10 + uint64(c-'0')
	}
	if port == 0 || port > 65535 {
		return "", 0, fmt.Errorf("port out of range: %d", port)
	}
	return host, uint16(port), nil
}
