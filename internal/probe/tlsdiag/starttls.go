// STARTTLS upgrade for protocols that negotiate TLS on top of a
// pre-existing plaintext connection (SMTP, IMAP, POP3, FTP,
// PostgreSQL). The handshake sequences are hard-coded — the agent
// never gets to inject arbitrary bytes into the wire.
//
// On success, the underlying connection is handed to crypto/tls for
// a normal handshake; the resulting connection state feeds back into
// the same report (negotiated version / cipher).
//
// On failure, the StartTLSReport is populated with the failure
// reason and the caller decides how to surface it (finding).

package tlsdiag

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// runStartTLS performs the protocol-specific upgrade then a TLS
// handshake. The returned report is never nil — callers receive a
// populated StartTLSReport even on failure so the LLM can see what
// went wrong.
func (a *Analyzer) runStartTLS(ctx context.Context, target *security.SafeTarget, opts DiagnoseOptions) *StartTLSReport {
	rep := &StartTLSReport{Protocol: opts.StartTLS}
	port := opts.Port
	if port == 0 {
		switch opts.StartTLS {
		case "smtp":
			port = 587
		case "imap":
			port = 143
		case "pop3":
			port = 110
		case "ftp":
			port = 21
		case "postgres":
			port = 5432
		default:
			rep.FailureReason = "unknown start_tls protocol"
			return rep
		}
	}

	dialFn := a.dialer.PinnedDialContext(target)
	rawConn, err := dialFn(ctx, "tcp", net.JoinHostPort(target.Hostname, strconv.Itoa(int(port))))
	if err != nil {
		rep.FailureReason = "dial failed: " + err.Error()
		return rep
	}
	defer func() { _ = rawConn.Close() }()

	br := bufio.NewReader(rawConn)
	deadline := time.Now().Add(a.cfg.HandshakeTimeout)
	if err := rawConn.SetDeadline(deadline); err != nil {
		rep.FailureReason = "set deadline: " + err.Error()
		return rep
	}

	runDialogue, ok := starttlsDialogues[opts.StartTLS]
	if !ok {
		rep.FailureReason = "unsupported start_tls protocol: " + opts.StartTLS
		return rep
	}
	if err := runDialogue(ctx, rawConn, br, rep); err != nil {
		rep.FailureReason = err.Error()
		return rep
	}

	// Re-arm deadlines so the TLS handshake can use the remaining
	// budget cleanly.
	if err := rawConn.SetDeadline(time.Now().Add(a.cfg.HandshakeTimeout)); err != nil {
		rep.FailureReason = "set deadline: " + err.Error()
		return rep
	}

	tlsCfg := a.tlsConfig(target, opts)
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		// The protocol upgrade succeeded — the TLS handshake is a
		// separate failure. We record UpgradeSucceeded=true so the
		// LLM sees the upgrade was offered and the cipher/version
		// fields stay populated if the handshake partially
		// succeeded (e.g. ServerHello received but cert rejected).
		rep.UpgradeSucceeded = true
		rep.FailureReason = "TLS handshake after STARTTLS: " + err.Error()
		state := tlsConn.ConnectionState()
		if v, ok := tlsVersionString[state.Version]; ok {
			rep.NegotiatedVersion = v
		}
		if state.CipherSuite != 0 {
			rep.NegotiatedCipher = tls.CipherSuiteName(state.CipherSuite)
		}
		_ = tlsConn.Close()
		return rep
	}
	state := tlsConn.ConnectionState()
	if v, ok := tlsVersionString[state.Version]; ok {
		rep.NegotiatedVersion = v
	}
	if state.CipherSuite != 0 {
		rep.NegotiatedCipher = tls.CipherSuiteName(state.CipherSuite)
	}
	rep.UpgradeSucceeded = true
	_ = tlsConn.Close()
	return rep
}

// starttlsDialogues returns the protocol-specific upgrade routine.
// Each entry MUST hard-code every byte sent on the wire.
var starttlsDialogues = map[string]starttlsDialogueFn{
	"smtp":     starttlsSMTP,
	"imap":     starttlsIMAP,
	"pop3":     starttlsPOP3,
	"ftp":      starttlsFTP,
	"postgres": starttlsPostgres,
}

type starttlsDialogueFn func(ctx context.Context, c net.Conn, br *bufio.Reader, rep *StartTLSReport) error

// readSMTPLine reads the next non-empty line of an SMTP dialogue
// (terminated by \r\n). Returns the trimmed line.
func readSMTPLine(br *bufio.Reader) (string, error) {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		return line, nil
	}
}

func starttlsSMTP(ctx context.Context, c net.Conn, br *bufio.Reader, rep *StartTLSReport) error {
	banner, err := readSMTPLine(br)
	if err != nil {
		return fmt.Errorf("smtp banner: %w", err)
	}
	rep.Banner = banner
	if !strings.HasPrefix(banner, "220 ") {
		return fmt.Errorf("smtp banner: unexpected %q", banner)
	}
	if _, err := fmt.Fprintf(c, "EHLO probe.local\r\n"); err != nil {
		return fmt.Errorf("smtp EHLO write: %w", err)
	}
	for {
		line, err := readSMTPLine(br)
		if err != nil {
			return fmt.Errorf("smtp EHLO read: %w", err)
		}
		// End of multiline response: "250 " line or "250-" continuation
		if strings.HasPrefix(line, "250 ") {
			break
		}
		if !strings.HasPrefix(line, "250-") {
			return fmt.Errorf("smtp EHLO: unexpected line %q", line)
		}
	}
	if _, err := fmt.Fprintf(c, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("smtp STARTTLS write: %w", err)
	}
	resp, err := readSMTPLine(br)
	if err != nil {
		return fmt.Errorf("smtp STARTTLS read: %w", err)
	}
	if !strings.HasPrefix(resp, "220 ") {
		return fmt.Errorf("smtp STARTTLS: server replied %q", resp)
	}
	if br.Buffered() != 0 {
		return fmt.Errorf("smtp STARTTLS: %d unexpected bytes buffered before TLS", br.Buffered())
	}
	return nil
}

func starttlsIMAP(ctx context.Context, c net.Conn, br *bufio.Reader, rep *StartTLSReport) error {
	banner, err := readSMTPLine(br)
	if err != nil {
		return fmt.Errorf("imap banner: %w", err)
	}
	rep.Banner = banner
	if !strings.HasPrefix(banner, "* OK") {
		return fmt.Errorf("imap banner: unexpected %q", banner)
	}
	if _, err := fmt.Fprintf(c, "a001 STARTTLS\r\n"); err != nil {
		return fmt.Errorf("imap STARTTLS write: %w", err)
	}
	resp, err := readSMTPLine(br)
	if err != nil {
		return fmt.Errorf("imap STARTTLS read: %w", err)
	}
	if !strings.HasPrefix(strings.ToUpper(resp), "A001 OK") {
		return fmt.Errorf("imap STARTTLS: server replied %q", resp)
	}
	if br.Buffered() != 0 {
		return fmt.Errorf("imap STARTTLS: %d unexpected bytes buffered before TLS", br.Buffered())
	}
	return nil
}

func starttlsPOP3(ctx context.Context, c net.Conn, br *bufio.Reader, rep *StartTLSReport) error {
	banner, err := readSMTPLine(br)
	if err != nil {
		return fmt.Errorf("pop3 banner: %w", err)
	}
	rep.Banner = banner
	if !strings.HasPrefix(banner, "+OK") {
		return fmt.Errorf("pop3 banner: unexpected %q", banner)
	}
	if _, err := fmt.Fprintf(c, "STLS\r\n"); err != nil {
		return fmt.Errorf("pop3 STLS write: %w", err)
	}
	resp, err := readSMTPLine(br)
	if err != nil {
		return fmt.Errorf("pop3 STLS read: %w", err)
	}
	if !strings.HasPrefix(resp, "+OK") {
		return fmt.Errorf("pop3 STLS: server replied %q", resp)
	}
	if br.Buffered() != 0 {
		return fmt.Errorf("pop3 STLS: %d unexpected bytes buffered before TLS", br.Buffered())
	}
	return nil
}

func starttlsFTP(ctx context.Context, c net.Conn, br *bufio.Reader, rep *StartTLSReport) error {
	banner, err := readSMTPLine(br)
	if err != nil {
		return fmt.Errorf("ftp banner: %w", err)
	}
	rep.Banner = banner
	if !strings.HasPrefix(banner, "220 ") {
		return fmt.Errorf("ftp banner: unexpected %q", banner)
	}
	if _, err := fmt.Fprintf(c, "AUTH TLS\r\n"); err != nil {
		return fmt.Errorf("ftp AUTH TLS write: %w", err)
	}
	resp, err := readSMTPLine(br)
	if err != nil {
		return fmt.Errorf("ftp AUTH TLS read: %w", err)
	}
	if !strings.HasPrefix(resp, "234 ") {
		return fmt.Errorf("ftp AUTH TLS: server replied %q", resp)
	}
	if br.Buffered() != 0 {
		return fmt.Errorf("ftp AUTH TLS: %d unexpected bytes buffered before TLS", br.Buffered())
	}
	return nil
}

// starttlsPostgres sends the SSLRequest packet (8 bytes) and waits
// for a single-byte response: 'S' (accept TLS), 'N' (no SSL).
// PostgreSQL has no plaintext banner; the upgrade is initiated by
// the client.
func starttlsPostgres(ctx context.Context, c net.Conn, br *bufio.Reader, rep *StartTLSReport) error {
	rep.Banner = ""
	// SSLRequest: length=8, code=80877103 (SSL_REQUEST).
	if _, err := c.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
		return fmt.Errorf("postgres SSLRequest write: %w", err)
	}
	resp, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("postgres SSLRequest read: %w", err)
	}
	if resp != 'S' {
		return fmt.Errorf("postgres SSLRequest: server replied %q", string(resp))
	}
	if br.Buffered() != 0 {
		return fmt.Errorf("postgres SSLRequest: %d unexpected bytes buffered before TLS", br.Buffered())
	}
	return nil
}
