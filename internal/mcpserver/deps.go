package mcpserver

import (
	"context"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/probe/tlsdiag"
	"github.com/bornholm/netprobe-mcp/internal/security"
)

// TCPDep bundles everything a tcp_probe handler needs.
type TCPDep struct {
	Prober      *probe.TCPProber
	DialTimeout time.Duration
}

func (t *TCPDep) Run(ctx context.Context, target *security.SafeTarget, dialer *security.SafeDialer, opts probe.TCPOptions) (*probe.Result, error) {
	return t.Prober.Run(ctx, target, dialer, opts)
}

// HTTPDep bundles everything an http_probe handler needs.
type HTTPDep struct {
	Prober        *probe.HTTPProber
	DialTimeout   time.Duration
	AllowRedirect bool
	MaxRedirects  int
}

func (h *HTTPDep) Run(ctx context.Context, target *security.SafeTarget, dialer *security.SafeDialer, opts probe.HTTPOptions, allowRedirect bool, guard *security.Guard) (*probe.Result, error) {
	return h.Prober.Run(ctx, target, dialer, opts, allowRedirect, guard)
}

// DNSDep bundles everything a dns_probe handler needs.
type DNSDep struct {
	Prober      *probe.DNSProber
	DialTimeout time.Duration
}

func (d *DNSDep) Run(ctx context.Context, target *security.SafeTarget, opts probe.DNSOptions) (*probe.Result, error) {
	return d.Prober.Run(ctx, target, opts)
}

// TLSDep bundles everything a tls_diagnose handler needs.
type TLSDep struct {
	Analyzer *tlsdiag.Analyzer
}

func (t *TLSDep) Run(ctx context.Context, target *security.SafeTarget, opts tlsdiag.DiagnoseOptions) (*tlsdiag.Report, error) {
	return t.Analyzer.Diagnose(target, opts)
}

// GRPCDep bundles everything a grpc_probe handler needs. Only the
// Health/Check method is exposed (PLAN §7.6).
type GRPCDep struct {
	Prober           *probe.GRPCProber
	DialTimeout      time.Duration
	DefaultPort      uint16
	HandshakeTimeout time.Duration
}

func (g *GRPCDep) Run(ctx context.Context, target *security.SafeTarget, dialer *security.SafeDialer, opts probe.GRPCOptions) (*probe.GRPCProbeResult, error) {
	return g.Prober.Run(ctx, target, dialer, opts)
}
