package tlsdiag

// AlwaysSkipped returns the list of checks the v1 analyzer is unable
// to perform regardless of input. The list is stable: a check that
// moves to a real rule in a future version is removed here.
//
// The reason strings are short because the MCP layer surfaces them
// directly to the LLM.
func AlwaysSkipped() []SkippedCheck {
	return []SkippedCheck{
		{
			Check:  "TLS_SSLV3_ENABLED",
			Reason: "SSLv3 removed from Go's crypto/tls; cannot probe acceptance",
		},
		{
			Check:  "TLS_WEAK_CIPHER_NULL",
			Reason: "NULL cipher suites removed from Go's crypto/tls; cannot probe acceptance",
		},
		{
			Check:  "TLS_WEAK_CIPHER_EXPORT",
			Reason: "EXPORT cipher suites removed from Go's crypto/tls; cannot probe acceptance",
		},
		{
			Check:  "TLS_WEAK_CIPHER_RC4",
			Reason: "RC4 removed from Go's crypto/tls; cannot probe acceptance",
		},
		{
			Check:  "TLS_WEAK_CIPHER_3DES",
			Reason: "3DES removed from Go's crypto/tls; cannot probe acceptance",
		},
		{
			Check:  "TLS_WEAK_DH_PARAMS",
			Reason: "DHE cipher suites unsupported by Go's crypto/tls client; cannot probe DH parameters",
		},
		{
			Check:  "TLS_INSECURE_RENEGOTIATION",
			Reason: "Go's crypto/tls client cannot initiate renegotiation; cannot probe",
		},
		{
			Check:  "TLS_COMPRESSION_ENABLED",
			Reason: "TLS compression removed from Go's crypto/tls; not negotiated",
		},
		{
			Check:  "TLS_AIA_FETCH",
			Reason: "disabled in v1: AIA URLs are controlled by the target certificate and would create a secondary SSRF channel",
		},
		{
			Check:  "TLS_OCSP_DIRECT_QUERY",
			Reason: "disabled in v1: OCSP responder URLs are controlled by the target certificate and would create a secondary SSRF channel",
		},
		{
			Check:  "TLS_PROTOCOLS_ENUM",
			Reason: "active phase disabled in v1: would require one handshake per protocol version",
		},
		{
			Check:  "TLS_CIPHER_SUITES_ENUM",
			Reason: "active phase disabled in v1: would require one handshake per cipher suite",
		},
		{
			Check:  "TLS_SNI_BEHAVIOUR",
			Reason: "active phase disabled in v1: requires a second handshake without SNI",
		},
		{
			Check:  "TLS_HSTS_CHECK",
			Reason: "not in v1 scope: requires an additional HTTP request to the same target",
		},
		{
			Check:  "TLS_HTTP_REDIRECT_CHECK",
			Reason: "not in v1 scope: requires a connection on port 80",
		},
		{
			Check:  "TLS_STARTLS",
			Reason: "not in v1 scope: STARTTLS upgrade requires protocol-specific handshakes",
		},
		{
			Check:  "TLS_ROCA_VULNERABLE_KEY",
			Reason: "ROCA detection is not implemented in v1; would require a dedicated prime-test library",
		},
		{
			Check:  "TLS_DEBIAN_WEAK_KEY",
			Reason: "Debian weak-key detection is not implemented in v1; would require a fingerprint database",
		},
		{
			Check:  "TLS_CERT_KEY_MISMATCH",
			Reason: "comparing leaf SPKI to handshake transient key requires forging a ClientHello; not in v1",
		},
	}
}
