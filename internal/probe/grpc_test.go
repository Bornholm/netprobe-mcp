package probe

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
	"github.com/bornholm/netprobe-mcp/internal/security"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// startFakeGRPCServer builds a TCP listener wrapped by an h2c
// handler so the Go stdlib client can speak plaintext HTTP/2 to it.
// healthyNames is the set of service names for which Health/Check
// returns SERVING; any other service (or empty) returns NOT_FOUND
// (grpc-status=5). Returns the listener, the bound host:port, a
// cleanup func, and a counter incremented on every request.
func startFakeGRPCServer(t *testing.T, healthyNames map[string]bool) (net.Listener, string, func(), *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/grpc.health.v1.Health/Check", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		service := sniffServiceName(r)
		// Trailers must be predeclared in the response Trailer
		// header BEFORE WriteHeader (per net/http docs).
		status := "0"
		msg := ""
		if service != "" && !healthyNames[service] {
			status = "5" // NOT_FOUND
			msg = "service not found: " + service
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.Header().Set("Grpc-Status", status)
		if msg != "" {
			w.Header().Set("Grpc-Message", msg)
		}
		w.WriteHeader(http.StatusOK)
		// Empty length-prefixed response body (zero bytes of
		// protobuf payload).
		_, _ = w.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
		// Drain the request body so the connection can close cleanly.
		_, _ = io.Copy(io.Discard, r.Body)
	})

	srv := &http.Server{
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	cleanup := func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}
	return ln, ln.Addr().String(), cleanup, &calls
}

// sniffServiceName reads the length-prefixed protobuf body off the
// request body and extracts the first string field, if any. We
// avoid pulling in a protobuf library for the tests by doing a
// best-effort decode of the field-1 wire format.
func sniffServiceName(r *http.Request) string {
	buf := make([]byte, 256)
	n, _ := r.Body.Read(buf)
	if n < 5 {
		return ""
	}
	// First byte: compressed flag (0 = uncompressed).
	// Next 4 bytes: message length (big-endian uint32).
	msgLen := uint32(buf[1])<<24 | uint32(buf[2])<<16 | uint32(buf[3])<<8 | uint32(buf[4])
	if msgLen == 0 || n < int(5+msgLen) {
		return ""
	}
	body := buf[5 : 5+msgLen]
	if len(body) == 0 {
		return ""
	}
	// HealthCheckRequest.service is field 1, wire type 2 (LEN).
	// Tag = (1 << 3) | 2 = 0x0a. Next byte(s) = varint length.
	if body[0] != 0x0a || len(body) < 2 {
		return ""
	}
	vl := int(body[1])
	if 2+vl > len(body) {
		return ""
	}
	return string(body[2 : 2+vl])
}

// testIPFilter builds an IPFilter that lets through 127.0.0.0/8 and
// no bogons.
func testIPFilter(t *testing.T) *security.IPFilter {
	t.Helper()
	cfg := &config.NetworkPolicy{
		AllowIPv4:            ptrTrue(),
		AllowIPv6:            ptrFalse(),
		DisableDefaultBogons: true,
		BlockLoopback:        ptrFalse(),
	}
	f, err := security.NewIPFilter(cfg)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	return f
}

func ptrTrue() *bool  { b := true; return &b }
func ptrFalse() *bool { b := false; return &b }

// safeTargetForAddr builds a SafeTarget pointing at the given
// 127.0.0.1:port pair, with the right defaults so the prober's
// port-mismatch check passes.
func safeTargetForAddr(t *testing.T, addr string) *security.SafeTarget {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	portNum, err := net.LookupPort("tcp", portStr)
	if err != nil {
		t.Fatalf("lookup %q: %v", portStr, err)
	}
	return &security.SafeTarget{
		Hostname: host,
		IP:       netip.MustParseAddr(host),
		Port:     uint16(portNum),
		Scheme:   "grpc",
	}
}

// TestGRPCProber_HappyPath starts a fake h2c gRPC server, points
// the prober at it, and verifies SERVING comes back.
func TestGRPCProber_HappyPath(t *testing.T) {
	_, addr, cleanup, calls := startFakeGRPCServer(t, map[string]bool{"": true})
	defer cleanup()

	target := safeTargetForAddr(t, addr)
	dialer, err := security.NewSafeDialer(config.NetworkPolicy{
		AllowIPv4:            ptrTrue(),
		AllowIPv6:            ptrFalse(),
		DisableDefaultBogons: true,
		BlockLoopback:        ptrFalse(),
	}, testIPFilter(t), 5*time.Second)
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}

	p := NewGRPCProber(5*time.Second, 50051)
	res, err := p.Run(context.Background(), target, dialer, GRPCOptions{
		Host: target.Hostname,
		Port: int(target.Port),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success=true, got false (err=%q grpc=%+v)", res.Error, res.GRPC)
	}
	if res.GRPC.HealthStatus != "SERVING" {
		t.Errorf("HealthStatus = %q, want SERVING", res.GRPC.HealthStatus)
	}
	if res.GRPC.GRPCStatus != "0" {
		t.Errorf("GRPCStatus = %q, want 0", res.GRPC.GRPCStatus)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server received %d calls, want 1", got)
	}
}

// TestGRPCProber_ServiceUnknown exercises the "specific service
// not found" path. The fake server returns grpc-status 5 for any
// service that isn't in healthyNames. The prober must surface
// SERVICE_UNKNOWN without treating it as a tool error.
func TestGRPCProber_ServiceUnknown(t *testing.T) {
	healthy := map[string]bool{"my.svc": true}
	_, addr, cleanup, _ := startFakeGRPCServer(t, healthy)
	defer cleanup()

	target := safeTargetForAddr(t, addr)
	dialer, _ := security.NewSafeDialer(config.NetworkPolicy{
		AllowIPv4: ptrTrue(), AllowIPv6: ptrFalse(),
		DisableDefaultBogons: true, BlockLoopback: ptrFalse(),
	}, testIPFilter(t), 5*time.Second)

	p := NewGRPCProber(5*time.Second, 50051)
	res, err := p.Run(context.Background(), target, dialer, GRPCOptions{
		Host:    target.Hostname,
		Port:    int(target.Port),
		Service: "does.not.exist",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Success {
		t.Errorf("expected Success=false for unknown service")
	}
	if res.GRPC.HealthStatus != "SERVICE_UNKNOWN" {
		t.Errorf("HealthStatus = %q, want SERVICE_UNKNOWN", res.GRPC.HealthStatus)
	}
	if res.GRPC.GRPCStatus != "5" {
		t.Errorf("GRPCStatus = %q, want 5", res.GRPC.GRPCStatus)
	}
	if !strings.Contains(res.GRPC.GRPCMessage, "does.not.exist") {
		t.Errorf("GRPCMessage should mention the bad service name, got %q", res.GRPC.GRPCMessage)
	}
}

// TestGRPCProber_RefusesUnknownPath verifies that hitting a path
// the server has not registered yields NOT SERVING. We use a fresh
// mux that does NOT register the Health/Check path, so a request
// to it returns 404 (mapped to UNIMPLEMENTED).
func TestGRPCProber_RefusesUnknownPath(t *testing.T) {
	mux := http.NewServeMux() // empty: no handlers
	srv := &http.Server{Handler: h2c.NewHandler(mux, &http2.Server{})}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	addr := ln.Addr().String()
	target := safeTargetForAddr(t, addr)
	dialer, _ := security.NewSafeDialer(config.NetworkPolicy{
		AllowIPv4: ptrTrue(), AllowIPv6: ptrFalse(),
		DisableDefaultBogons: true, BlockLoopback: ptrFalse(),
	}, testIPFilter(t), 5*time.Second)

	p := NewGRPCProber(5*time.Second, 50051)
	res, err := p.Run(context.Background(), target, dialer, GRPCOptions{
		Host: target.Hostname,
		Port: int(target.Port),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Success {
		t.Errorf("expected failure against a non-gRPC server, got %+v", res.GRPC)
	}
}

// TestGRPCProber_ConnectionRefused ensures the prober surfaces a
// connection refused error as Success=false with a network error
// class, not as a tool error.
func TestGRPCProber_ConnectionRefused(t *testing.T) {
	// Bind and immediately close to get an unused port.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	target := safeTargetForAddr(t, addr)
	dialer, _ := security.NewSafeDialer(config.NetworkPolicy{
		AllowIPv4: ptrTrue(), AllowIPv6: ptrFalse(),
		DisableDefaultBogons: true, BlockLoopback: ptrFalse(),
	}, testIPFilter(t), time.Second)

	p := NewGRPCProber(time.Second, 50051)
	res, err := p.Run(context.Background(), target, dialer, GRPCOptions{
		Host: target.Hostname,
		Port: int(target.Port),
	})
	if err != nil {
		t.Fatalf("Run returned tool-level error: %v", err)
	}
	if res.Success {
		t.Errorf("expected Success=false for connection refused")
	}
	if res.ErrorClass == "" {
		t.Errorf("expected non-empty ErrorClass")
	}
}

// TestGRPCProber_RejectsNegativePort ensures the prober refuses
// malformed input before touching the network.
func TestGRPCProber_RejectsNegativePort(t *testing.T) {
	target := &security.SafeTarget{Hostname: "127.0.0.1", IP: netip.MustParseAddr("127.0.0.1"), Port: 80}
	dialer, _ := security.NewSafeDialer(config.NetworkPolicy{
		AllowIPv4: ptrTrue(), AllowIPv6: ptrFalse(),
		DisableDefaultBogons: true, BlockLoopback: ptrFalse(),
	}, testIPFilter(t), time.Second)
	p := NewGRPCProber(time.Second, 50051)
	if _, err := p.Run(context.Background(), target, dialer, GRPCOptions{Host: "127.0.0.1", Port: -1}); err == nil {
		t.Fatal("expected error for negative port")
	}
}

// TestGRPCProber_RejectsPortMismatch ensures that if the operator
// forgets to align the call's port with the SafeTarget's port,
// the prober refuses before dialling.
func TestGRPCProber_RejectsPortMismatch(t *testing.T) {
	target := &security.SafeTarget{Hostname: "127.0.0.1", IP: netip.MustParseAddr("127.0.0.1"), Port: 80}
	dialer, _ := security.NewSafeDialer(config.NetworkPolicy{
		AllowIPv4: ptrTrue(), AllowIPv6: ptrFalse(),
		DisableDefaultBogons: true, BlockLoopback: ptrFalse(),
	}, testIPFilter(t), time.Second)
	p := NewGRPCProber(time.Second, 50051)
	if _, err := p.Run(context.Background(), target, dialer, GRPCOptions{Host: "127.0.0.1", Port: 81}); err == nil {
		t.Fatal("expected error for port mismatch")
	}
}

// TestGRPCHealthStatusMapping covers the table that maps
// (httpStatus, grpcStatus) → health enum.
func TestGRPCHealthStatusMapping(t *testing.T) {
	cases := []struct {
		name       string
		httpStatus int
		grpcStatus string
		want       string
	}{
		{"ok-and-zero", 200, "0", "SERVING"},
		{"ok-but-not-found", 200, "5", "SERVICE_UNKNOWN"},
		{"unauthenticated", 401, "", "PERMISSION_DENIED"},
		{"not-found-no-grpc", 404, "", "UNIMPLEMENTED"},
		{"unavailable", 503, "", "UNAVAILABLE"},
		{"unknown-status", 200, "999", "UNKNOWN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := healthStatusFromGRPC(tc.httpStatus, tc.grpcStatus)
			if got != tc.want {
				t.Errorf("healthStatusFromGRPC(%d, %q) = %q, want %q",
					tc.httpStatus, tc.grpcStatus, got, tc.want)
			}
		})
	}
}

// TestBuildHealthCheckRequest verifies the hand-rolled protobuf
// encoding. The shape is observable to the server side; if it
// regresses the SERVICE_UNKNOWN test fails too, but this unit
// test makes the failure mode easier to read.
func TestBuildHealthCheckRequest(t *testing.T) {
	t.Run("empty service yields zero-length message", func(t *testing.T) {
		got := buildHealthCheckRequest("")
		want := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
		if !bytesEq(got, want) {
			t.Errorf("empty: got %v, want %v", got, want)
		}
	})
	t.Run("non-empty service encodes tag + length + bytes", func(t *testing.T) {
		got := buildHealthCheckRequest("foo")
		want := []byte{
			0x00,                   // compressed flag
			0x00, 0x00, 0x00, 0x05, // msg length = 5 (tag + varint + 3 bytes)
			0x0a, 0x03, 'f', 'o', 'o',
		}
		if !bytesEq(got, want) {
			t.Errorf("foo: got %v, want %v", got, want)
		}
	})
	t.Run("oversized service is truncated to 127", func(t *testing.T) {
		svc := strings.Repeat("a", 200)
		got := buildHealthCheckRequest(svc)
		// Expected length: 5 header + 2 (tag + varint=127) + 127 = 134
		if len(got) != 134 {
			t.Errorf("truncated length = %d, want 134", len(got))
		}
	})
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
