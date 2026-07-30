// Active cipher suite enumeration. Performs several handshakes
// against the authorized target, each restricted to a specific
// subset of cipher suites, to classify what the server is willing
// to negotiate.
//
// InsecureSkipVerify=true is REQUIRED for the same reason as in
// protocols.go: we are measuring negotiation, not validity. The
// setting is confined to this file by
// TestInsecureSkipVerifyIsConfined.

package tlsdiag

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// cipherGroup defines a logical group of cipher suites used to
// classify a server. Each probe consists of one handshake offering
// only the suites in the group; success implies the server accepts
// at least one suite from that group.
type cipherGroup struct {
	id    string
	label string
	// weak is true when the group contains suites considered
	// cryptographically broken or deprecated.
	weak bool
	// fields of CipherSuiteReport toggled on success.
	apply func(*CipherSuiteReport)
}

// cipherGroups is the catalogue of probes. The order matters only
// for diagnostics; the resulting flags are independent.
var cipherGroups = []cipherGroup{
	{
		id:    "fs",
		label: "Forward-secrecy (ECDHE/DHE)",
		weak:  false,
		apply: func(r *CipherSuiteReport) { r.ForwardSecrecy = true },
	},
	{
		id:    "cbc_sha1",
		label: "CBC + HMAC-SHA1 (Lucky13)",
		weak:  true,
		apply: func(r *CipherSuiteReport) { r.WeakCBCSHA1 = true },
	},
	{
		id:    "3des",
		label: "3DES (SWEET32)",
		weak:  true,
		apply: func(r *CipherSuiteReport) { r.Weak3DES = true },
	},
	{
		id:    "rc4",
		label: "RC4 (deprecated)",
		weak:  true,
		apply: func(r *CipherSuiteReport) { r.WeakRC4 = true },
	},
	{
		id:    "null",
		label: "NULL cipher (no encryption)",
		weak:  true,
		apply: func(r *CipherSuiteReport) { r.WeakNULL = true },
	},
	{
		id:    "export",
		label: "EXPORT suites (FREAK)",
		weak:  true,
		apply: func(r *CipherSuiteReport) { r.WeakExport = true },
	},
	{
		id:    "anon",
		label: "Anonymous suites (no auth)",
		weak:  true,
		apply: func(r *CipherSuiteReport) { r.WeakAnon = true },
	},
}

// probeCipherSuites iterates over cipherGroups and runs one
// handshake per group. The returned CipherSuiteReport has each
// boolean flag set to true when the corresponding group was at
// least offered by the server.
//
// Some groups (NULL, EXPORT, RC4) cannot be tested with
// crypto/tls because those suites are no longer compiled into
// Go's runtime. The corresponding probe will fail by construction
// (the runtime refuses to send a ClientHello containing them).
// We document this in Note for the LLM's benefit.
func (a *Analyzer) probeCipherSuites(ctx context.Context, target *security.SafeTarget) CipherSuiteReport {
	rep := CipherSuiteReport{
		Note: "NULL/EXPORT/RC4 suites removed from Go's crypto/tls; corresponding flags cannot be detected and remain false unless future code uses utls.",
	}
	dialFn := a.dialer.PinnedDialContext(target)
	for _, group := range cipherGroups {
		if ctx.Err() != nil {
			break
		}
		if !cipherGroupProbeable(group) {
			continue
		}
		if err := a.probeCipherGroup(ctx, target, dialFn, group); err == nil {
			group.apply(&rep)
		}
	}
	return rep
}

// cipherGroupSuites returns the cipher suite IDs that belong to a
// group. Empty slice means "no detectable suite" — Go's runtime
// has dropped the corresponding codes.
func cipherGroupSuites(group cipherGroup) []uint16 {
	switch group.id {
	case "fs":
		return []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		}
	case "cbc_sha1":
		return []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		}
	case "3des":
		return []uint16{
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		}
	case "rc4":
		// RC4 has been removed from Go's TLS implementation; the
		// constants still exist for completeness but proposing
		// them in CipherSuites results in the handshake being
		// rejected client-side.
		return nil
	case "null":
		return nil
	case "export":
		return nil
	case "anon":
		// Go's runtime no longer carries anonymous suites in the
		// active constants. Returning an empty list keeps the
		// group unprobeable, same as RC4/NULL/EXPORT.
		return nil
	}
	return nil
}

// cipherGroupProbeable returns false when the group has no
// detectable suite in Go's runtime. The corresponding probe is
// skipped and the corresponding report flag stays false.
func cipherGroupProbeable(group cipherGroup) bool {
	return len(cipherGroupSuites(group)) > 0
}

// probeCipherGroup opens one handshake with only the cipher
// suites of the requested group offered. Returns nil on a
// successful handshake regardless of certificate validity.
func (a *Analyzer) probeCipherGroup(ctx context.Context, target *security.SafeTarget, dialFn func(context.Context, string, string) (net.Conn, error), group cipherGroup) error {
	hsCtx, cancel := context.WithTimeout(ctx, a.cfg.HandshakeTimeout)
	defer cancel()

	cfg := &tls.Config{
		ServerName: target.Hostname,
		MinVersion: a.cfg.MinTLSVersion,
		MaxVersion: a.cfg.MaxTLSVersion,
		// Justification: same as protocols.go — measuring
		// negotiation, not validity. Allowed only by
		// TestInsecureSkipVerifyIsConfined.
		InsecureSkipVerify: true, //nolint:gosec // intentional, justified above
		Time:               a.now,
		CipherSuites:       cipherGroupSuites(group),
	}

	rawConn, err := dialFn(hsCtx, "tcp", net.JoinHostPort(target.Hostname, itoa(int(target.Port))))
	if err != nil {
		return err
	}
	defer func() { _ = rawConn.Close() }()

	tlsConn := tls.Client(rawConn, cfg)
	defer func() { _ = tlsConn.Close() }()

	return tlsConn.HandshakeContext(hsCtx)
}
