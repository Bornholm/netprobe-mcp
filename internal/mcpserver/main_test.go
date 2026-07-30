package mcpserver

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("net.(*TCPListener).Accept"),
		goleak.IgnoreTopFunction("github.com/bornholm/netprobe-mcp/internal/audit.(*Logger).run"),
	)
}

// quietListener is a TCP listener used to keep the goroutine leak detector
// happy in tests that don't read from a connection.
func quietListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-Test\r\n"))
				select {
				case <-ctx.Done():
				case <-time.After(50 * time.Millisecond):
				}
			}(c)
		}
	}()
	return ln
}
