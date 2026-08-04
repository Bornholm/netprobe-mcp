package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/metrics"
	"github.com/bornholm/netprobe-mcp/internal/ratelimit"
	"github.com/bornholm/netprobe-mcp/internal/security"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Deps struct {
	Guard        *security.Guard
	Limiter      *ratelimit.Manager
	Audit        *audit.Logger
	Metrics      *metrics.Registry
	Logger       *slog.Logger
	TCPProber    *TCPDep
	HTTPProber   *HTTPDep
	DNSProber    *DNSDep
	ICMPProber   *ICMPDep
	GRPCProber   *GRPCDep
	TLSDiagnoser *TLSDep
	Instructions string
	Config       *config.Config
}

type Server struct {
	mcp         *mcp.Server
	guard       *security.Guard
	dialer      *security.SafeDialer
	limiter     *ratelimit.Manager
	audit       *audit.Logger
	metrics     *metrics.Registry
	logger      *slog.Logger
	tcpProber   *TCPDep
	httpProber  *HTTPDep
	dnsProber   *DNSDep
	icmpProber  *ICMPDep
	grpcProber  *GRPCDep
	tlsDiagnose *TLSDep
	cfg         *config.Config
}

func New(impl *mcp.Implementation, deps Deps) *Server {
	opts := &mcp.ServerOptions{
		Instructions: deps.Instructions,
	}
	mcpSrv := mcp.NewServer(impl, opts)

	s := &Server{
		mcp:         mcpSrv,
		guard:       deps.Guard,
		dialer:      deps.Guard.Dialer(),
		limiter:     deps.Limiter,
		audit:       deps.Audit,
		metrics:     deps.Metrics,
		logger:      deps.Logger,
		tcpProber:   deps.TCPProber,
		httpProber:  deps.HTTPProber,
		dnsProber:   deps.DNSProber,
		icmpProber:  deps.ICMPProber,
		grpcProber:  deps.GRPCProber,
		tlsDiagnose: deps.TLSDiagnoser,
		cfg:         deps.Config,
	}

	mcpSrv.AddReceivingMiddleware(auditMiddleware(deps.Audit, deps.Logger))
	mcpSrv.AddReceivingMiddleware(recoveryMiddleware(deps.Logger))

	if err := s.registerTools(); err != nil {
		deps.Logger.Error("register tools failed", slog.Any("err", err))
	}
	s.registerResources()
	if deps.HTTPProber != nil {
		if err := s.registerHTTPProbe(); err != nil {
			deps.Logger.Error("register http_probe failed", slog.Any("err", err))
		}
	}
	if deps.DNSProber != nil {
		if err := s.registerDNSProbe(); err != nil {
			deps.Logger.Error("register dns_probe failed", slog.Any("err", err))
		}
	}
	if deps.ICMPProber != nil {
		if err := s.registerICMPProbe(); err != nil {
			deps.Logger.Error("register icmp_probe failed", slog.Any("err", err))
		}
	}
	if deps.GRPCProber != nil {
		if err := s.registerGRPCProbe(); err != nil {
			deps.Logger.Error("register grpc_probe failed", slog.Any("err", err))
		}
	}
	if deps.TLSDiagnoser != nil {
		if err := s.registerTLSDiagnose(); err != nil {
			deps.Logger.Error("register tls_diagnose failed", slog.Any("err", err))
		}
	}
	return s
}

func (s *Server) MCP() *mcp.Server { return s.mcp }

// auditMiddleware logs every received MCP method invocation; structured for
// later correlation with probe results.
//
// Decision routing:
//   - If the handler returned an *auditEventErr (MarkDenied/MarkInternal),
//     the carried event is emitted verbatim and no synthetic event is
//     generated on top.
//   - Otherwise a synthetic event is emitted: success by default; if the
//     transport returned an error, outcome=internal_error.
func auditMiddleware(a *audit.Logger, log *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			start := time.Now()
			sessionID := ""
			if req != nil {
				if s := req.GetSession(); s != nil {
					sessionID = s.ID()
				}
			}
			res, err := next(ctx, method, req)
			dur := time.Since(start)

			if a != nil && method == "tools/call" {
				if hint, ok := unwrapAuditEvent(err); ok && hint != nil {
					if hint.DurationMs == 0 {
						hint.DurationMs = float64(dur.Microseconds()) / 1000.0
					}
					if hint.SessionID == "" {
						hint.SessionID = sessionID
					}
					a.Emit(hint)
					err = nil // strip the audit-event marker from the surfaced error
				} else if ctr, ok := req.(*mcp.CallToolRequest); ok {
					ev := &audit.Event{
						SessionID:  sessionID,
						Tool:       ctr.Params.Name,
						Decision:   "allowed",
						Outcome:    audit.OutcomeSuccess,
						DurationMs: float64(dur.Microseconds()) / 1000.0,
					}
					if err != nil {
						ev.Outcome = audit.OutcomeInternal
						ev.DenyReason = err.Error()
					}
					a.Emit(ev)
				}
			}
			log.Debug("mcp method", slog.String("method", method), slog.String("session", sessionID), slog.Duration("dur", dur), slog.Any("err", err))
			return res, err
		}
	}
}

// recoveryMiddleware converts panics into structured errors so a single
// bad request cannot crash the server process.
func recoveryMiddleware(log *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (res mcp.Result, err error) {
			defer func() {
				if r := recover(); r != nil {
					log.Error("mcp panic", slog.String("method", method), slog.Any("panic", r))
					err = fmt.Errorf("internal error: %v", r)
				}
			}()
			return next(ctx, method, req)
		}
	}
}
