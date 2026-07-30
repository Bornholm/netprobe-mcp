// Tests for the HTTP transport (Streamable HTTP + Bearer auth +
// Origin guard). Coverage:
//   - token validation (valid, invalid, missing)
//   - origin guard (allowed list)
//   - 401 with WWW-Authenticate when token missing/invalid
//   - 403 when Origin is rejected
//   - happy path with a synthetic authorized mcp.Server
//
// These tests are hermetic: they build an in-memory http.Handler
// via newHTTPHandler and use httptest to fire requests at it. No
// goroutine leak detector here — we already lean on goleak at the
// package level for that.
package mcpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/audit"
	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// sha256Hex returns the lowercase hex SHA-256 of s.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}

// newHTTPTestServer builds a Server wired with the minimum
// subsystems the HTTP handler needs. Distinct from newTestServer
// in integration_test.go which builds a fully-capable MCP server.
func newHTTPTestServer(t *testing.T, cfg *config.Config, allowOrigins []string) *Server {
	t.Helper()
	if cfg == nil {
		cfg = config.Default()
	}
	cfg.Server.Transport = "http"
	cfg.Server.HTTPConfig.AllowedOrigins = append([]string{}, allowOrigins...)
	cfg.Server.HTTPConfig.Addr = "127.0.0.1:0"

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditLogger, err := audit.New(audit.Config{Format: "json", Output: "stderr", Level: "info"})
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })

	s := &Server{
		mcp:    mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, &mcp.ServerOptions{}),
		logger: log,
		audit:  auditLogger,
		cfg:    cfg,
	}
	return s
}

// TestNewHTTPHandler_AuthMissing verifies that a request without
// the Authorization header is rejected with 401.
func TestNewHTTPHandler_AuthMissing(t *testing.T) {
	cfg := config.Default()
	cfg.Server.HTTPConfig.Auth.TokenBearer.Enabled = true
	cfg.Server.HTTPConfig.Auth.TokenBearer.TokenHashes = []string{
		sha256Hex("secret-token"),
	}

	s := newHTTPTestServer(t, cfg, []string{"https://allowed.example"})
	handler, err := newHTTPHandler(s.mcp, s, s.logger)
	if err != nil {
		t.Fatalf("newHTTPHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("expected WWW-Authenticate header, got none")
	}
}

// TestNewHTTPHandler_AuthInvalid verifies that a request with a wrong
// token is rejected with 401.
func TestNewHTTPHandler_AuthInvalid(t *testing.T) {
	cfg := config.Default()
	cfg.Server.HTTPConfig.Auth.TokenBearer.Enabled = true
	cfg.Server.HTTPConfig.Auth.TokenBearer.TokenHashes = []string{
		sha256Hex("correct-token"),
	}

	s := newHTTPTestServer(t, cfg, []string{})
	handler, err := newHTTPHandler(s.mcp, s, s.logger)
	if err != nil {
		t.Fatalf("newHTTPHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// TestNewHTTPHandler_AuthValid_DeniedByOrigin verifies that even a
// request with a valid token is rejected when the Origin is not on
// the allow-list.
func TestNewHTTPHandler_AuthValid_DeniedByOrigin(t *testing.T) {
	cfg := config.Default()
	cfg.Server.HTTPConfig.Auth.TokenBearer.Enabled = true
	cfg.Server.HTTPConfig.Auth.TokenBearer.TokenHashes = []string{
		sha256Hex("good"),
	}

	s := newHTTPTestServer(t, cfg, []string{"https://allowed.example"})
	handler, err := newHTTPHandler(s.mcp, s, s.logger)
	if err != nil {
		t.Fatalf("newHTTPHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("got status %d, want %d", w.Code, http.StatusForbidden)
	}
}

// TestNewHTTPHandler_AuthValid_AllowedOrigin verifies the happy
// path: a valid token + allowed Origin reaches the MCP handler.
// We do not care about the MCP response shape here (a properly
// initialized initialize handshake is out of scope for this
// transport test); we only require that the request is NOT
// 401/403-blocked by our middleware.
func TestNewHTTPHandler_AuthValid_AllowedOrigin(t *testing.T) {
	cfg := config.Default()
	cfg.Server.HTTPConfig.Auth.TokenBearer.Enabled = true
	cfg.Server.HTTPConfig.Auth.TokenBearer.TokenHashes = []string{
		sha256Hex("good"),
	}

	s := newHTTPTestServer(t, cfg, []string{"https://allowed.example"})
	handler, err := newHTTPHandler(s.mcp, s, s.logger)
	if err != nil {
		t.Fatalf("newHTTPHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("Origin", "https://allowed.example")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Errorf("got status %d; auth+origin let the request through", w.Code)
	}
}

// TestNewHTTPHandler_OriginEmpty_NoBrowserMode verifies the
// no-browser default: an empty origin list means any request
// carrying an Origin header is rejected, even with a valid token.
func TestNewHTTPHandler_OriginEmpty_NoBrowserMode(t *testing.T) {
	cfg := config.Default()
	cfg.Server.HTTPConfig.Auth.TokenBearer.Enabled = true
	cfg.Server.HTTPConfig.Auth.TokenBearer.TokenHashes = []string{
		sha256Hex("good"),
	}
	cfg.Server.HTTPConfig.AllowedOrigins = nil

	s := newHTTPTestServer(t, cfg, nil)
	handler, err := newHTTPHandler(s.mcp, s, s.logger)
	if err != nil {
		t.Fatalf("newHTTPHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("Origin", "https://allowed.example")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("got status %d, want 403 (no-browser mode)", w.Code)
	}
}

// TestBearerTokenAuth_ConstantTime ensures that no matter where
// the matching token sits in the list, the request is accepted.
// (We do not measure timing here; this test merely confirms
// functional correctness across positions.)
func TestBearerTokenAuth_ConstantTime(t *testing.T) {
	tokens := []string{"first", "second", "third", "fourth"}
	hashes := make([]string, len(tokens))
	for i, tok := range tokens {
		hashes[i] = sha256Hex(tok)
	}

	cfg := config.TokenBearerAuth{Enabled: true, TokenHashes: hashes}
	a, err := newBearerTokenAuth(cfg)
	if err != nil {
		t.Fatalf("newBearerTokenAuth: %v", err)
	}

	for _, tok := range tokens {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		a.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("token %q: got status %d, want %d", tok, w.Code, http.StatusOK)
		}
	}
}

// TestNewHTTPHandler_NoAuth_RejectsAtBuildTime mirrors the runtime
// invariant: newHTTPHandler returns an error when no auth provider
// is enabled. This is what blocks the deny-by-default invariant
// when the validator is bypassed.
func TestNewHTTPHandler_NoAuth_RejectsAtBuildTime(t *testing.T) {
	cfg := config.Default()
	cfg.Server.HTTPConfig.Auth.TokenBearer.Enabled = false

	s := newHTTPTestServer(t, cfg, []string{})
	_, err := newHTTPHandler(s.mcp, s, s.logger)
	if err == nil {
		t.Errorf("expected error when no auth provider is configured")
	}
}

// TestRunHTTP_TokenHashValidation exercises the RunHTTP entry
// point by binding to an ephemeral loopback port and issuing a
// request with a wrong token. The handler must reply 401.
func TestRunHTTP_TokenHashValidation(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Transport = "http"
	cfg.Server.HTTPConfig.Addr = "127.0.0.1:0"
	cfg.Server.HTTPConfig.Auth.TokenBearer.Enabled = true
	cfg.Server.HTTPConfig.Auth.TokenBearer.TokenHashes = []string{
		sha256Hex("right"),
	}

	s := newHTTPTestServer(t, cfg, []string{})

	// We don't bind RunHTTP for real (it would require port
	// allocation); instead we exercise the handler directly via a
	// httptest server with our wrapped handler.
	handler, err := newHTTPHandler(s.mcp, s, s.logger)
	if err != nil {
		t.Fatalf("newHTTPHandler: %v", err)
	}
	ts := httptest.NewServer(handler)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	body, _ := io.ReadAll(resp.Body)
	// Confirm the response body is JSON, sanity-check the schema.
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Errorf("response body is not valid JSON: %v (%s)", err, string(body))
	}
}

// TestBindAddrIsLoopback covers the helper that audits non-loopback
// binds.
func TestBindAddrIsLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"127.0.0.1:1", true},
		{"localhost:9000", true},
		{"0.0.0.0:80", false},
		{"192.0.2.1:443", false},
		{"[::1]:8080", true},
		{"[2001:db8::1]:443", false},
		{"not-a-valid-addr", false},
		{":8080", true},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			if got := bindAddrIsLoopback(tc.addr); got != tc.want {
				t.Errorf("bindAddrIsLoopback(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}
