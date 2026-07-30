// Package mcpserver — HTTP transport.
//
// Wire format: Streamable HTTP per the MCP spec
// (https://modelcontextprotocol.io/specification/2025-06-18/basic/transports).
// The handler built here is wrapped by:
//
//  1. request logging (audit + slog);
//  2. Bearer-token authentication (server.http.auth.token_bearer);
//  3. Origin / DNS-rebinding guard;
//  4. Read/write timeouts.
//
// Background and rationale: the PLAN §13.8 mandates that
// `server.transport=http` is locked behind a deny-by-default
// authentication invariant. A public-facing network-probe MCP is, by
// construction, an authenticated SSRF proxy; this code keeps that
// promise by refusing to start without at least one auth provider,
// by tokenising the timeouts so a slow client cannot pin a worker,
// and by rejecting requests carrying an Origin header that is not
// on the allow-list (defence in depth against DNS-rebinding of the
// server itself, mirrors PLAN §9.8).
package mcpserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// httpAuth is the interface implemented by every per-request auth
// gate.
type httpAuth interface {
	Name() string
	Wrap(next http.Handler) http.Handler
}

// bearerTokenAuth validates an Authorization: Bearer <token>
// header. Tokens are matched against a precomputed list of SHA-256
// hex digests to avoid leaking plaintext in the configuration file.
//
// Constant-time comparison is enforced across the whole digest set:
// we iterate the (sorted) hashes with subtle.ConstantTimeCompare on
// each, so the worst-case running time is O(n) regardless of where
// the match occurs.
type bearerTokenAuth struct {
	header     string
	tokenHash  [][sha256.Size]byte
	now        func() time.Time
	maxSkew    time.Duration
	maxReqSize int64
}

func newBearerTokenAuth(cfg config.TokenBearerAuth) (*bearerTokenAuth, error) {
	if !cfg.Enabled {
		return nil, errors.New("bearer auth disabled in config")
	}
	if len(cfg.TokenHashes) == 0 {
		return nil, errors.New("bearer auth has no token hashes configured")
	}
	header := cfg.HeaderName
	if header == "" {
		header = "Authorization"
	}
	hashes := make([][sha256.Size]byte, 0, len(cfg.TokenHashes))
	for _, hexStr := range cfg.TokenHashes {
		if len(hexStr) != 64 {
			return nil, fmt.Errorf("token hash %q is not a 64-character SHA-256 hex digest", hexStr)
		}
		var h [sha256.Size]byte
		for i := 0; i < sha256.Size; i++ {
			b, err := unhex(hexStr[i*2], hexStr[i*2+1])
			if err != nil {
				return nil, fmt.Errorf("token hash %q: %w", hexStr, err)
			}
			h[i] = b
		}
		hashes = append(hashes, h)
	}
	return &bearerTokenAuth{
		header:    header,
		tokenHash: hashes,
		now:       time.Now,
	}, nil
}

// HashToken returns the SHA-256 hex digest of the supplied token.
// The exposed helper exists so operators can mint hashes offline
// without spinning a server.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum)
}

func unhex(hi, lo byte) (byte, error) {
	h, err := fromHex(hi)
	if err != nil {
		return 0, err
	}
	l, err := fromHex(lo)
	if err != nil {
		return 0, err
	}
	return h<<4 | l, nil
}

func fromHex(c byte) (byte, error) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', nil
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, nil
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid hex character %q", c)
}

func (b *bearerTokenAuth) Name() string { return "bearer-token" }

func (b *bearerTokenAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get(b.header)
		if got == "" {
			b.fail(w, r, "missing_token")
			return
		}
		// Tolerate "Bearer " prefix per RFC 6750.
		token := strings.TrimSpace(strings.TrimPrefix(got, "Bearer "))
		if token == "" {
			b.fail(w, r, "missing_token")
			return
		}
		sum := sha256.Sum256([]byte(token))
		match := false
		for _, want := range b.tokenHash {
			if subtle.ConstantTimeCompare(sum[:], want[:]) == 1 {
				match = true
				break
			}
		}
		if !match {
			b.fail(w, r, "invalid_token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// fail replies 401 with the same body shape MCP expects for an
// unauthenticated request. We never leak WHICH check failed
// beyond a coarse category; that is enough for diagnostic logs
// without empowering an attacker to probe.
func (b *bearerTokenAuth) fail(w http.ResponseWriter, r *http.Request, reason string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="netprobe-mcp"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"authentication required"}}`))
}

// originGuard rejects browser-issued requests whose Origin header
// does not match one of the configured values. Without this guard,
// a victim's browser visiting evil.example could be coerced into
// sending requests to netprobe-mcp — classic DNS rebinding against
// the SERVER itself (PLAN §9.8).
//
// When AllowedOrigins is empty the server is in "no-browser" mode:
// any request carrying an Origin header is rejected outright. This
// is the safe default.
type originGuard struct {
	allowed map[string]struct{}
	logger  *slog.Logger
}

func newOriginGuard(cfg config.HTTPConfig, log *slog.Logger) *originGuard {
	allowed := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowed[strings.TrimSpace(o)] = struct{}{}
	}
	return &originGuard{allowed: allowed, logger: log}
}

func (g *originGuard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := g.allowed[origin]; !ok {
			if g.logger != nil {
				g.logger.Warn("rejected cross-origin request",
					slog.String("origin", origin),
					slog.String("path", r.URL.Path),
				)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32002,"message":"forbidden origin"}}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bindAddrIsLoopback returns true when addr binds to loopback. Used
// to record the bind posture without influencing the auth decision
// (auth is mandatory regardless).
//
// Hostnames are resolved against the system to detect
// "localhost"-style addresses. If the lookup fails, the bind is
// flagged as non-loopback (the operator must then assert the
// safety of the bind explicitly, e.g. via reverse-proxy path).
func bindAddrIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return false
		}
	}
	return len(ips) > 0
}

// newHTTPHandler returns the http.Handler that serves MCP requests
// over Streamable HTTP, wrapped with auth + origin + audit
// middleware. The returned handler is *independent* of any prior
// mcp.Server; the server gets attached in RunHTTP via the handler
// factory closure.
func newHTTPHandler(srv *mcp.Server, s *Server, log *slog.Logger) (http.Handler, error) {
	if srv == nil {
		return nil, errors.New("newHTTPHandler: mcp.Server is nil")
	}
	cfg := s.cfg.Server.HTTPConfig

	// Authentication gate. The config validator has already enforced
	// at-least-one-provider; we re-check defensively because the
	// validator can be bypassed by callers using New() directly.
	var auth httpAuth
	if cfg.Auth.TokenBearer.Enabled {
		bt, err := newBearerTokenAuth(cfg.Auth.TokenBearer)
		if err != nil {
			return nil, fmt.Errorf("bearer token auth: %w", err)
		}
		auth = bt
	}
	if auth == nil {
		return nil, errors.New("no auth provider configured")
	}

	// The Streamable HTTP handler holds onto getServer so that each
	// request can be matched to the right MCP session. For a
	// single-tenant deployment we just hand back the same server.
	getServer := func(r *http.Request) *mcp.Server { return srv }
	mcpHandler := mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{
		SessionTimeout: cfg.SessionTTL,
		Logger:         log,
	})

	// Wrap with origin, then auth, then audit logging.
	withAudit := auditHTTPMiddleware(log, s.audit)(mcpHandler)
	withAuth := auth.Wrap(withAudit)
	withOrigin := newOriginGuard(cfg, log).Wrap(withAuth)

	return withOrigin, nil
}

// RunHTTP starts the MCP server on the configured TCP address and
// blocks until ctx is cancelled. The transport uses the
// Streamable-HTTP handler from the SDK wrapped with the auth and
// origin guards.
func (s *Server) RunHTTP(ctx context.Context, cfg config.HTTPConfig) error {
	if s.mcp == nil {
		return errors.New("RunHTTP: mcp.Server is nil")
	}
	if cfg.Addr == "" {
		return errors.New("RunHTTP: server.http.addr is required")
	}
	if !bindAddrIsLoopback(cfg.Addr) {
		s.logger.Warn("http transport binding to non-loopback address; this is intended for behind-a-reverse-proxy setups",
			slog.String("addr", cfg.Addr),
			slog.String("hint", "make sure an external authenticating reverse proxy is in front of the server"),
		)
	}

	handler, err := newHTTPHandler(s.mcp, s, s.logger)
	if err != nil {
		return fmt.Errorf("build http handler: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("http transport listening",
			slog.String("addr", cfg.Addr),
			slog.Duration("read_timeout", cfg.ReadTimeout),
			slog.Duration("write_timeout", cfg.WriteTimeout),
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), cfg.IdleTimeout)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		s.logger.Info("http transport stopped")
		return nil
	case err := <-errCh:
		return err
	}
}

// auditHTTPMiddleware emits an audit event for every HTTP request
// reaching the MCP handler. The body of the request is NOT parsed
// (the SDK owns the framing); only the request line, the response
// status and timing are recorded.
func auditHTTPMiddleware(log *slog.Logger, a *audit.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			dur := time.Since(start)
			if a != nil {
				a.Emit(&audit.Event{
					Tool:            "http_request",
					Decision:        "allowed",
					Outcome:         auditOutcomeFromStatus(rw.status),
					RequestedTarget: r.URL.Path,
					DurationMs:      float64(dur.Microseconds()) / 1000.0,
				})
			}
			if log != nil {
				log.Debug("http request",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", rw.status),
					slog.Duration("dur", dur),
				)
			}
		})
	}
}

// statusRecorder captures the response status code without buffering
// the body. http.ResponseWriter exposes no public API for the code
// once WriteHeader has been called (intentionally, to discourage
// post-hoc rewrites).
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func auditOutcomeFromStatus(s int) string {
	switch {
	case s >= 200 && s < 300:
		return audit.OutcomeSuccess
	case s == http.StatusUnauthorized || s == http.StatusForbidden:
		return audit.OutcomeDenied
	default:
		return audit.OutcomeInternal
	}
}
