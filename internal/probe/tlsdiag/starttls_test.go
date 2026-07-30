// Tests for the STARTTLS upgrade active phase. Each test spins up
// a minimal in-memory server that follows the protocol-specific
// banner / upgrade sequence, then asserts that runStartTLS either
// succeeds or fails with the expected reason.

package tlsdiag

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// smtpServer returns a plaintext SMTP-ish server. If offerStartTLS
// is true, EHLO is followed by STARTTLS acceptance; otherwise it
// is followed by "502 STARTTLS not implemented".
func smtpServer(t *testing.T, offerStartTLS bool) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				// 220 banner
				c.Write([]byte("220 smtp.test ready\r\n"))
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					up := strings.ToUpper(line)
					switch {
					case strings.HasPrefix(up, "EHLO"):
						c.Write([]byte("250-smtp.test\r\n250 STARTTLS\r\n"))
					case strings.HasPrefix(up, "STARTTLS"):
						if offerStartTLS {
							c.Write([]byte("220 go ahead\r\n"))
							// Upgrade done. Wait a moment so the
							// client can read.
							time.Sleep(100 * time.Millisecond)
							return
						}
						c.Write([]byte("502 not implemented\r\n"))
						return
					case strings.HasPrefix(up, "QUIT"):
						c.Write([]byte("221 bye\r\n"))
						return
					default:
						c.Write([]byte("500 unknown\r\n"))
					}
				}
			}(conn)
		}
	}()
	cleanup := func() {
		close(done)
		_ = ln.Close()
	}
	return ln.Addr().String(), cleanup
}

func imapServer(t *testing.T, offerStartTLS bool) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				c.Write([]byte("* OK imap.test ready\r\n"))
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					up := strings.ToUpper(line)
					if strings.HasPrefix(up, "A001 STARTTLS") {
						if offerStartTLS {
							c.Write([]byte("a001 OK go ahead\r\n"))
							time.Sleep(100 * time.Millisecond)
							return
						}
						c.Write([]byte("a001 NO not implemented\r\n"))
						return
					}
					if strings.HasPrefix(up, "A001 LOGOUT") {
						c.Write([]byte("* BYE\r\na001 OK\r\n"))
						return
					}
				}
			}(conn)
		}
	}()
	cleanup := func() {
		close(done)
		_ = ln.Close()
	}
	return ln.Addr().String(), cleanup
}

func pop3Server(t *testing.T, offerStartTLS bool) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				c.Write([]byte("+OK pop3.test ready\r\n"))
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					up := strings.ToUpper(line)
					if strings.HasPrefix(up, "STLS") {
						if offerStartTLS {
							c.Write([]byte("+OK go ahead\r\n"))
							time.Sleep(100 * time.Millisecond)
							return
						}
						c.Write([]byte("-ERR not implemented\r\n"))
						return
					}
					if strings.HasPrefix(up, "QUIT") {
						c.Write([]byte("+OK bye\r\n"))
						return
					}
				}
			}(conn)
		}
	}()
	cleanup := func() {
		close(done)
		_ = ln.Close()
	}
	return ln.Addr().String(), cleanup
}

func ftpServer(t *testing.T, offerStartTLS bool) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				c.Write([]byte("220 ftp.test ready\r\n"))
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					up := strings.ToUpper(line)
					if strings.HasPrefix(up, "AUTH TLS") {
						if offerStartTLS {
							c.Write([]byte("234 go ahead\r\n"))
							time.Sleep(100 * time.Millisecond)
							return
						}
						c.Write([]byte("500 not implemented\r\n"))
						return
					}
					if strings.HasPrefix(up, "QUIT") {
						c.Write([]byte("221 bye\r\n"))
						return
					}
				}
			}(conn)
		}
	}()
	cleanup := func() {
		close(done)
		_ = ln.Close()
	}
	return ln.Addr().String(), cleanup
}

func postgresServer(t *testing.T, offerStartTLS bool) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				// Read 8 bytes (SSLRequest packet).
				buf := make([]byte, 8)
				if _, err := readFull(br, buf); err != nil {
					return
				}
				if offerStartTLS {
					c.Write([]byte{'S'})
					time.Sleep(100 * time.Millisecond)
				} else {
					c.Write([]byte{'N'})
				}
			}(conn)
		}
	}()
	cleanup := func() {
		close(done)
		_ = ln.Close()
	}
	return ln.Addr().String(), cleanup
}

// readFull reads exactly len(buf) bytes or returns an error.
func readFull(br *bufio.Reader, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := br.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func splitHostPortLocal(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return host, uint16(p)
}

func TestStartTLS_SMTP_Offered(t *testing.T) {
	addr, stop := smtpServer(t, true)
	defer stop()
	host, port := splitHostPortLocal(t, addr)
	tgt := &security.SafeTarget{Hostname: host, IP: netip.MustParseAddr(host), Port: port}
	a := analyzerStubWithDialer(t, nil)
	rep := a.runStartTLS(testContext(t), tgt, DiagnoseOptions{StartTLS: "smtp", Port: port})
	if rep == nil {
		t.Fatalf("expected non-nil report")
	}
	if !rep.UpgradeSucceeded {
		t.Errorf("expected upgrade to succeed, got reason=%q", rep.FailureReason)
	}
}

func TestStartTLS_SMTP_NotOffered(t *testing.T) {
	addr, stop := smtpServer(t, false)
	defer stop()
	host, port := splitHostPortLocal(t, addr)
	tgt := &security.SafeTarget{Hostname: host, IP: netip.MustParseAddr(host), Port: port}
	a := analyzerStubWithDialer(t, nil)
	rep := a.runStartTLS(testContext(t), tgt, DiagnoseOptions{StartTLS: "smtp", Port: port})
	if rep == nil {
		t.Fatalf("expected non-nil report")
	}
	if rep.UpgradeSucceeded {
		t.Errorf("expected upgrade to fail, got success")
	}
	if rep.FailureReason == "" {
		t.Errorf("expected non-empty failure reason")
	}
}

func TestStartTLS_IMAP_NotOffered(t *testing.T) {
	addr, stop := imapServer(t, false)
	defer stop()
	host, port := splitHostPortLocal(t, addr)
	tgt := &security.SafeTarget{Hostname: host, IP: netip.MustParseAddr(host), Port: port}
	a := analyzerStubWithDialer(t, nil)
	rep := a.runStartTLS(testContext(t), tgt, DiagnoseOptions{StartTLS: "imap", Port: port})
	if rep.UpgradeSucceeded {
		t.Errorf("expected IMAP upgrade to fail")
	}
}

func TestStartTLS_POP3_NotOffered(t *testing.T) {
	addr, stop := pop3Server(t, false)
	defer stop()
	host, port := splitHostPortLocal(t, addr)
	tgt := &security.SafeTarget{Hostname: host, IP: netip.MustParseAddr(host), Port: port}
	a := analyzerStubWithDialer(t, nil)
	rep := a.runStartTLS(testContext(t), tgt, DiagnoseOptions{StartTLS: "pop3", Port: port})
	if rep.UpgradeSucceeded {
		t.Errorf("expected POP3 upgrade to fail")
	}
}

func TestStartTLS_FTP_NotOffered(t *testing.T) {
	addr, stop := ftpServer(t, false)
	defer stop()
	host, port := splitHostPortLocal(t, addr)
	tgt := &security.SafeTarget{Hostname: host, IP: netip.MustParseAddr(host), Port: port}
	a := analyzerStubWithDialer(t, nil)
	rep := a.runStartTLS(testContext(t), tgt, DiagnoseOptions{StartTLS: "ftp", Port: port})
	if rep.UpgradeSucceeded {
		t.Errorf("expected FTP upgrade to fail")
	}
}

func TestStartTLS_Postgres_Offered(t *testing.T) {
	addr, stop := postgresServer(t, true)
	defer stop()
	host, port := splitHostPortLocal(t, addr)
	tgt := &security.SafeTarget{Hostname: host, IP: netip.MustParseAddr(host), Port: port}
	a := analyzerStubWithDialer(t, nil)
	// We can't fully complete the handshake because we don't have a
	// real TLS server on the upgrade side, but the upgrade itself
	// should report success before the TLS handshake fails.
	rep := a.runStartTLS(testContext(t), tgt, DiagnoseOptions{StartTLS: "postgres", Port: port})
	if !rep.UpgradeSucceeded {
		t.Errorf("expected postgres upgrade to succeed, got reason=%q", rep.FailureReason)
	}
}

func TestStartTLS_Postgres_NotOffered(t *testing.T) {
	addr, stop := postgresServer(t, false)
	defer stop()
	host, port := splitHostPortLocal(t, addr)
	tgt := &security.SafeTarget{Hostname: host, IP: netip.MustParseAddr(host), Port: port}
	a := analyzerStubWithDialer(t, nil)
	rep := a.runStartTLS(testContext(t), tgt, DiagnoseOptions{StartTLS: "postgres", Port: port})
	if rep.UpgradeSucceeded {
		t.Errorf("expected postgres upgrade to fail when responder says N")
	}
}

func TestStartTLS_UnknownProtocol(t *testing.T) {
	tgt := safeTargetStub("127.0.0.1")
	a := analyzerStub(nil)
	rep := a.runStartTLS(testContext(t), tgt, DiagnoseOptions{StartTLS: "weird"})
	if rep == nil {
		t.Fatalf("expected non-nil report")
	}
	if rep.UpgradeSucceeded {
		t.Errorf("expected unknown protocol to fail")
	}
	if rep.FailureReason == "" {
		t.Errorf("expected non-empty failure reason")
	}
	_ = tls.Config{} // keep import
}
