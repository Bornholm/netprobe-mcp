// SNI-vs-default comparison. The check answers one question: when a
// client connects WITHOUT an SNI extension (the legacy behaviour
// before RFC 6066 §3), does the server return the same certificate
// as when it connects WITH the requested SNI?
//
// A mismatch is a strong signal of two things:
//
//  1. The server hosts multiple TLS virtual hosts on a single
//     listener. Legacy clients (embedded libraries, OpenSSL s_client
//     without -servername, very old Java) silently receive the
//     "default" certificate which does not match their hostname.
//
//  2. The default server block is not configured to reject
//     no-SNI connections. Operators who want strict SNI typically
//     set ssl_reject_handshake on (nginx) or an equivalent
//     directive — its absence is itself a finding.
//
// This check is opt-in (ProbeSNIBehaviour) and is disabled in v1
// because it requires a second full handshake against the same
// target, which is moderately expensive and can trip cheap
// rate-limiting on the server side. See PLAN.md §8.5.

package tlsdiag

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"strconv"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

// SNIReport is the result of the SNI-vs-default probe. The
// comparison is only meaningful when NoSNIHandshakeSucceeded is
// true AND a non-empty fingerprint was returned.
type SNIReport struct {
	SNISent                 string `json:"sni_sent,omitempty"`
	NoSNIHandshakeSucceeded bool   `json:"no_sni_handshake_succeeded"`
	NoSNISubject            string `json:"no_sni_subject,omitempty"`
	NoSNIIssuer             string `json:"no_sni_issuer,omitempty"`
	NoSNIFingerprint        string `json:"no_sni_fingerprint,omitempty"`
	NoSNIError              string `json:"no_sni_error,omitempty"`
	SNIMismatch             bool   `json:"sni_mismatch"`
	Note                    string `json:"note,omitempty"`
}

// probeSNI performs a single handshake without SNI and compares the
// resulting leaf fingerprint against the one from the canonical
// (SNI-enabled) handshake.
//
// withSNILeaf is the leaf certificate the canonical handshake
// returned. When nil the comparison is skipped and SNIReport.SNIMismatch
// stays false with a note explaining why — this preserves the
// function safety for direct tests.
func (a *Analyzer) probeSNI(ctx context.Context, target *security.SafeTarget, withSNILeaf *x509.Certificate, opts DiagnoseOptions) SNIReport {
	rep := SNIReport{
		SNISent: opts.ServerNameOr(target),
	}

	bareCfg := &tls.Config{
		// ServerName intentionally left empty to bypass SNI.
		MinVersion: a.cfg.MinTLSVersion,
		MaxVersion: a.cfg.MaxTLSVersion,
		// The bare handshake is purely diagnostic: we want to see
		// what the server returns WITHOUT a ServerName, even if
		// the returned cert would not normally validate. This
		// mirrors the InsecureSkipVerify confinement documented
		// in insecure_guard_test.go (sni.go is added there).
		InsecureSkipVerify: true,
		Time:               a.now,
	}

	dialFn := a.dialer.PinnedDialContext(target)
	rawConn, err := dialFn(ctx, "tcp", net.JoinHostPort(target.Hostname, strconv.Itoa(int(target.Port))))
	if err != nil {
		rep.NoSNIError = err.Error()
		return rep
	}
	tlsConn := tls.Client(rawConn, bareCfg)
	hsErr := tlsConn.HandshakeContext(ctx)
	state := tlsConn.ConnectionState()
	_ = tlsConn.Close()

	if hsErr != nil {
		rep.NoSNIError = hsErr.Error()
		return rep
	}
	if len(state.PeerCertificates) == 0 {
		rep.NoSNIError = "no peer certificates"
		return rep
	}

	leaf := state.PeerCertificates[0]
	rep.NoSNIHandshakeSucceeded = true
	rep.NoSNISubject = leaf.Subject.String()
	rep.NoSNIIssuer = leaf.Issuer.String()
	rep.NoSNIFingerprint = fingerprintSHA256Hex(leaf.Raw)

	if withSNILeaf == nil {
		rep.Note = "no SNI leaf available for comparison"
		return rep
	}
	rep.SNIMismatch = (rep.NoSNIFingerprint != fingerprintSHA256Hex(withSNILeaf.Raw))
	return rep
}

// fingerprintSHA256Hex returns the lowercase hex SHA-256 of the DER
// representation of a certificate. The function is duplicated here
// (rather than imported from another file in the package) to keep the
// SNI module self-contained.
func fingerprintSHA256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
