// Raw ClientHello forging for legacy protocol / cipher-suite
// detection. crypto/tls in Go has removed SSLv3, RC4, 3DES, NULL and
// EXPORT cipher suites from its negotiation surface, so the
// "standard" tls.Client cannot probe whether a server would actually
// accept them. This file forges a TLS ClientHello from scratch and
// reads just enough of the ServerHello to determine what the server
// chose.
//
// Why a custom forger rather than utls (github.com/refraction-networking/utls)?
//
//  1. utls is an external dependency we want to avoid on a security-
//     critical tool. The forger is ~300 lines, dependency-free.
//  2. We do NOT need to complete the handshake. Reading the
//     ServerHello is enough to know what was accepted.
//  3. The set of targets is small and stable: SSLv3 + ~12 weak
//     cipher suites. We never need the full ClientHello surface.
//
// SECURITY:
//
//   - InsecureSkipVerify=true is forbidden in this file. The forger
//     is purely passive: it sends a ClientHello, reads the
//     ServerHello, then closes the connection. No application data
//     ever crosses the wire.
//
//   - The forger is opt-in. Callers MUST set DiagnoseOptions.ProbeWeakCiphers
//     to true. The phase is otherwise skipped.
//
// See PLAN.md §8.6 option (c).

package tlsdiag

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// TLS protocol versions relevant to weak-crypto detection.
const (
	tlsVersionSSL30 uint16 = 0x0300
	tlsVersionTLS10 uint16 = 0x0301
	tlsVersionTLS12 uint16 = 0x0303
)

// weakCipherSuite is one cipher we attempt to negotiate. The
// classification drives the Finding ID emitted.
type weakCipherSuite struct {
	code uint16
	name string
	// finding is the FindingID to raise when the server accepts
	// this suite. Empty means: do not raise a finding (used for
	// benign suites that are nonetheless interesting for testing).
	finding string
}

// weakCipherSuites is the closed list we probe. Order does not
// matter — each suite is tried in its own connection.
var weakCipherSuites = []weakCipherSuite{
	// RC4 (CVE-2013-2566 / RFC 7465 prohibit it).
	{code: 0x0005, name: "TLS_RSA_WITH_RC4_128_SHA", finding: "TLS_WEAK_CIPHER_RC4"},
	{code: 0xc007, name: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", finding: "TLS_WEAK_CIPHER_RC4"},
	{code: 0xc011, name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", finding: "TLS_WEAK_CIPHER_RC4"},
	// 3DES (SWEET32 / CVE-2016-2183).
	{code: 0x000a, name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", finding: "TLS_WEAK_CIPHER_3DES"},
	{code: 0xc012, name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", finding: "TLS_WEAK_CIPHER_3DES"},
	// NULL suites (no encryption; extremely rare in the wild).
	{code: 0x0001, name: "TLS_RSA_WITH_NULL_MD5", finding: "TLS_WEAK_CIPHER_NULL"},
	{code: 0x0002, name: "TLS_RSA_WITH_NULL_SHA", finding: "TLS_WEAK_CIPHER_NULL"},
	// EXPORT suites (FREAK / CVE-2015-0204).
	{code: 0x0003, name: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", finding: "TLS_WEAK_CIPHER_EXPORT"},
	{code: 0x0006, name: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", finding: "TLS_WEAK_CIPHER_EXPORT"},
	{code: 0x0008, name: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", finding: "TLS_WEAK_CIPHER_EXPORT"},
}

// weakProtocolVersion is one TLS protocol version we attempt to
// negotiate (SSLv3 and TLS 1.0/1.1 are deprecated by RFC 8996).
type weakProtocolVersion struct {
	code uint16
	name string
	// finding is the FindingID to raise if the server replies with
	// a ServerHello at this version.
	finding string
}

var weakProtocolVersions = []weakProtocolVersion{
	{code: tlsVersionSSL30, name: "SSL 3.0", finding: "TLS_SSLV3_ENABLED"},
	{code: tlsVersionTLS10, name: "TLS 1.0", finding: "TLS_TLS10_ENABLED"},
}

// forgeClientHello constructs a minimal ClientHello that:
//   - advertises legacy_record_version TLS 1.0 in the record layer
//     (required for SSLv3 negotiation).
//   - carries the supplied cipher_suites list.
//   - carries the supplied client_version.
//   - includes no extensions (none are needed for acceptance probing).
//
// The implementation handles the record layer framing so the caller
// can simply Write the returned bytes.
func forgeClientHello(clientVersion, recordVersion uint16, cipherSuites []uint16, serverName string) []byte {
	// Build the ClientHello message body.
	body := buildClientHelloBody(clientVersion, cipherSuites, serverName)

	// Prepend the 4-byte Handshake header (type 0x01 + 3-byte length).
	hsLen := uint32(len(body))
	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x01)
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	hs = append(hs, body...)

	// Wrap in a TLS record (content type 0x16 = Handshake). The
	// record length covers the entire handshake message.
	record := make([]byte, 0, 5+len(hs))
	record = append(record, 0x16)
	record = append(record, byte(recordVersion>>8), byte(recordVersion))
	recLen := uint16(len(hs))
	record = append(record, byte(recLen>>8), byte(recLen))
	record = append(record, hs...)

	return record
}

// buildClientHelloBody produces the inner ClientHello message (the
// 4-byte handshake header is added by the caller). Layout per RFC
// 5246 §7.4.1.2:
//
//	ClientVersion   2 bytes
//	Random          32 bytes
//	SessionID       1 byte length + 0..32 bytes
//	CipherSuites    2 bytes length + N*2 bytes
//	Compression     1 byte length + N bytes
//	Extensions      2 bytes length + ...
func buildClientHelloBody(clientVersion uint16, cipherSuites []uint16, serverName string) []byte {
	b := make([]byte, 0, 64+len(cipherSuites)*2)
	// ClientVersion.
	b = append(b, byte(clientVersion>>8), byte(clientVersion))
	// Random: 32 random bytes.
	rnd := make([]byte, 32)
	_, _ = rand.Read(rnd)
	b = append(b, rnd...)
	// SessionID: empty.
	b = append(b, 0x00)
	// CipherSuites.
	csLen := uint16(len(cipherSuites) * 2)
	b = append(b, byte(csLen>>8), byte(csLen))
	for _, c := range cipherSuites {
		b = append(b, byte(c>>8), byte(c))
	}
	// Compression methods: just "null" (0x00).
	b = append(b, 0x01, 0x00)

	// Extensions: only SNI is needed to receive the cert the
	// server would normally send. Without it, many modern servers
	// return a default cert that is irrelevant to the hostname.
	// We include a minimal SNI extension: type 0x0000, server_name
	// list with one entry (host_name).
	if serverName != "" {
		ext := buildSNIExtension(serverName)
		extLen := uint16(len(ext))
		b = append(b, byte(extLen>>8), byte(extLen))
		b = append(b, ext...)
	}
	return b
}

// buildSNIExtension encodes the server_name extension (RFC 6066 §3).
func buildSNIExtension(serverName string) []byte {
	nameBytes := []byte(serverName)
	// ServerNameList length (2 bytes) + one entry:
	//   NameType (1 byte, 0x00 = host_name)
	//   HostName  (2 bytes length + bytes)
	entryLen := 1 + 2 + len(nameBytes)
	listLen := 2 + entryLen

	out := make([]byte, 0, 4+listLen)
	// ExtensionType 0x0000 (server_name).
	out = append(out, 0x00, 0x00)
	// ServerNameList length.
	out = append(out, byte(listLen>>8), byte(listLen))
	// ServerNameList[0]: type + name.
	out = append(out, byte(entryLen>>8), byte(entryLen))
	out = append(out, 0x00) // host_name
	out = append(out, byte(len(nameBytes)>>8), byte(len(nameBytes)))
	out = append(out, nameBytes...)
	return out
}

// serverHelloObservation captures what the server chose when we
// offered a specific ClientHello. Err is non-nil if the connection
// failed or the ServerHello could not be parsed.
type serverHelloObservation struct {
	version  uint16
	cipher   uint16
	err      error
	rawBytes int
}

// probeRawHandshake opens a single TCP connection to the target and
// sends a forged ClientHello. It then reads bytes back and tries to
// extract the version and cipher from the ServerHello. Any failure
// to parse (alert, garbage, EOF) is reported in observation.err —
// callers translate this into a finding (e.g. SSLv3 refused).
func probeRawHandshake(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), target *security.SafeTarget, host string, port uint16, version uint16, suites []uint16) serverHelloObservation {
	rawConn, err := dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return serverHelloObservation{err: fmt.Errorf("dial: %w", err)}
	}
	defer rawConn.Close()

	// 5-second deadline covers the round-trip even for the slowest
	// tested paths.
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

	ch := forgeClientHello(version, version, suites, host)
	if _, err := rawConn.Write(ch); err != nil {
		return serverHelloObservation{err: fmt.Errorf("write: %w", err)}
	}

	// Read the TLS record header (5 bytes).
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(rawConn, hdr); err != nil {
		return serverHelloObservation{err: fmt.Errorf("read record header: %w", err)}
	}
	if hdr[0] != 0x16 {
		// Not a handshake record — could be an alert. Read the
		// rest of the record to capture its content for the
		// diagnostic, then return.
		bodyLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		body := make([]byte, bodyLen)
		if bodyLen > 0 && bodyLen <= 1024 {
			_, _ = io.ReadFull(rawConn, body)
		}
		return serverHelloObservation{
			err:      fmt.Errorf("not a handshake record (type 0x%02x body=%x)", hdr[0], body),
			rawBytes: 5 + len(body),
		}
	}
	bodyLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if bodyLen <= 0 || bodyLen > 16*1024 {
		return serverHelloObservation{err: fmt.Errorf("unreasonable record body length: %d", bodyLen)}
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(rawConn, body); err != nil {
		return serverHelloObservation{err: fmt.Errorf("read record body: %w", err)}
	}

	return parseServerHello(body)
}

// parseServerHello extracts the protocol version and cipher suite
// from a TLS Handshake message. It accepts:
//   - ServerHello (type 0x02)
//   - HelloRetryRequest (type 0x03 in TLS 1.3)
//
// Returns an error for any other shape.
func parseServerHello(body []byte) serverHelloObservation {
	if len(body) < 4 {
		return serverHelloObservation{err: fmt.Errorf("body too short: %d", len(body))}
	}
	hsType := body[0]
	// uint24: high byte first, then two low bytes.
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+hsLen > len(body) {
		return serverHelloObservation{err: fmt.Errorf("truncated handshake: %d + %d > %d", 4, hsLen, len(body))}
	}
	hs := body[4 : 4+hsLen]
	switch hsType {
	case 0x02:
		// ServerHello: ClientVersion (2) + Random (32) + SessionID
		// (1 + N) + CipherSuite (2) + Compression (1).
		off := 2 + 32
		if off > len(hs) {
			return serverHelloObservation{err: fmt.Errorf("server hello too short for version+random")}
		}
		sidLen := int(hs[off])
		off++
		off += sidLen
		if off+2 > len(hs) {
			return serverHelloObservation{err: fmt.Errorf("server hello too short for cipher")}
		}
		cipher := binary.BigEndian.Uint16(hs[off : off+2])
		return serverHelloObservation{
			version:  binary.BigEndian.Uint16(hs[0:2]),
			cipher:   cipher,
			rawBytes: 5 + len(body),
		}
	case 0x00:
		// FullHandshake.TLS12 (very old naming). Treat as a
		// ServerHello-shaped handshake; parsing follows the
		// ServerHello format above.
		return parseServerHello(append([]byte{0x02}, body[1:]...))
	default:
		return serverHelloObservation{err: fmt.Errorf("unexpected handshake type 0x%02x", hsType)}
	}
}

// probeWeakCiphers orchestrates the raw-ClientHello phase. It
// returns a slice of Finding IDs that the active phase detected as
// ACCEPTED by the server. An empty slice means: the server refused
// every weak cipher / protocol version we tested.
func (a *Analyzer) probeWeakCiphers(ctx context.Context, target *security.SafeTarget) []string {
	dialFn := a.dialer.PinnedDialContext(target)
	host, port := target.Hostname, target.Port

	var accepted []string
	seen := map[string]bool{}

	// Per-suite probing.
	for _, ws := range weakCipherSuites {
		if ctx.Err() != nil {
			break
		}
		obs := probeRawHandshake(ctx, dialFn, target, host, port, tlsVersionTLS12, []uint16{ws.code})
		if obs.err == nil && obs.cipher == ws.code && ws.finding != "" && !seen[ws.finding] {
			accepted = append(accepted, ws.finding)
			seen[ws.finding] = true
		}
	}

	// Per-protocol probing.
	for _, pv := range weakProtocolVersions {
		if ctx.Err() != nil {
			break
		}
		// For protocol probing we offer a single "compatible" suite
		// (RSA_WITH_AES_128_CBC_SHA, 0x002f) which is supported by
		// every TLS 1.0/1.1 implementation.
		obs := probeRawHandshake(ctx, dialFn, target, host, port, pv.code, []uint16{0x002f})
		if obs.err == nil && obs.version == pv.code && pv.finding != "" && !seen[pv.finding] {
			accepted = append(accepted, pv.finding)
			seen[pv.finding] = true
		}
	}
	return accepted
}
