package audit

import (
	"net/netip"
	"regexp"
	"strings"
)

// internalAddrRe matches IPv4 and IPv6 addresses from reserved,
// private, link-local, loopback, CGNAT and cloud-metadata ranges.
// The goal is to scrub internal network topology from the audit
// stream before it leaves the host.
//
// PLAN §11.1: "Remplacer les IPv4 privées (127/8, 10/8, 172.16/12,
// 192.168/16), loopback (127/8), link-local (169.254/16), CGNAT
// (100.64/10) et IPv6 ULA/link-local par [internal-ip]."
var internalAddrRe = regexp.MustCompile(
	// IPv4: 127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16,
	// 172.16.0.0/12, 192.168.0.0/16.
	`(?:127\.(?:\d{1,3}\.){2}\d{1,3}|` +
		`10\.(?:\d{1,3}\.){2}\d{1,3}|` +
		// CGNAT: 100.64/10 means second octet in [64..127].
		`100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}|` +
		`169\.254\.(?:\d{1,3}\.)?\d{1,3}|` +
		`172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)?\d{1,3}|` +
		`192\.168\.(?:\d{1,3}\.)?\d{1,3})`,
)

// internalAddrRe6 matches the IPv6 ranges that should be scrubbed
// from the audit stream: loopback, ULA, link-local, NAT64, the
// v4-in-v6 transition range and IPv6 cloud metadata.
var internalAddrRe6 = regexp.MustCompile(
	`(?:::1|` + // loopback
		`f[cd][0-9a-f]{2}:[0-9a-f:]+|` + // ULA fc00::/7
		`fe80:[0-9a-f:]+|` + // link-local fe80::/10
		`64:ff9b:[0-9a-f:]+|` + // NAT64
		`::ffff:[0-9a-f:]+|` + // v4-in-v6
		`fd00:ec2:[0-9a-f:]+)`, // AWS IPv6 metadata
)

// scrubIP returns "[internal-ip]" when s contains an internal
// address, otherwise returns s untouched. The function is
// conservative: if the regex matches, the whole string is replaced.
// That matches the plan's intent ("replace internal addresses")
// even when the address sits inside a longer URL or hostname
// (e.g. http://10.0.0.5:8080/path). The redactor does not try to
// preserve syntax — the audit log is not parsed by anyone after
// emission.
func scrubIP(s string) string {
	if s == "" {
		return s
	}
	if internalAddrRe.MatchString(s) || internalAddrRe6.MatchString(s) {
		return "[internal-ip]"
	}
	// Catch IPv6 literals without explicit prefix (e.g. fc00::1).
	if addr, err := netip.ParseAddr(s); err == nil {
		if isInternal(addr) {
			return "[internal-ip]"
		}
	}
	return s
}

// isInternal mirrors the rules used by security.IPFilter.Check for
// the common cases. Used to scrub audit strings where the IP
// literal is unambiguous.
func isInternal(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified()
}

// maxTargetLen caps the length of any audit-log string field that
// contains user-controlled input. 200 bytes is well below typical
// terminal widths but generous enough for any reasonable URL or
// hostname.
const maxTargetLen = 200

// sanitizeTarget applies the full scrub to a single audit string:
// replace internal IPs and truncate to a bounded length.
//
// This is the function referenced from PLAN §11.1 ("sanitizeErr")
// but renamed to better describe its scope: it acts on any target
// field that may contain operator-controlled or remote-controlled
// input.
func sanitizeTarget(s string) string {
	if s == "" {
		return s
	}
	s = scrubIP(s)
	if len(s) > maxTargetLen {
		s = s[:maxTargetLen] + "\u2026" // ellipsis, single rune
	}
	return s
}

// scrubOutboundURL sanitizes a URL that came from the certificate
// chain (AIA, OCSP responder) before it lands in the audit log. We
// scrub the host portion and the path separately so the URL stays
// legible: scheme://[internal-ip]:port/path rather than the full
// URL.
//
// URL parsing failure is treated as "no scrubbing needed": the raw
// string is still truncated to maxTargetLen.
func scrubOutboundURL(raw string) string {
	if raw == "" {
		return raw
	}
	// Cheap host extraction: try to split on "://" first.
	if idx := strings.Index(raw, "://"); idx >= 0 {
		rest := raw[idx+3:]
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		hostPart := rest[:end]
		scrubbed := scrubIP(hostPart)
		if scrubbed != hostPart {
			return raw[:idx+3] + scrubbed + rest[end:]
		}
	}
	return sanitizeTarget(raw)
}
