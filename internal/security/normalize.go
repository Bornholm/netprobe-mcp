package security

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// hostnameLabelRe enforces the DNS label syntax (RFC 1035) after normalization.
// Labels are 1..63 chars of [a-z0-9-], not starting or ending with '-'.
var hostnameLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// queryNameLabelRe is hostnameLabelRe with the underscore admitted.
//
// A DNS query name is not a host name. RFC 8552 reserves an entire family
// of underscored names for exactly the records an operator asks a probe
// about: _dmarc.example.com, selector._domainkey.example.com,
// _sip._tcp.example.com, _25._tcp.example.com. Refusing them makes DMARC,
// DKIM, SRV and TLSA unmeasurable — and the refusal reads as "malformed",
// which invites the caller to conclude the record is missing rather than
// unasked.
//
// The underscore is admitted anywhere inside a label, not only in front of
// one: DKIM selectors are operator-chosen strings and "s1_2024._domainkey"
// is as legitimate as "_dmarc". Restricting it to a prefix would rebuild a
// narrower version of the same trap. What this widens is one character of
// alphabet; what keeps a query name from becoming a tunnel is the length,
// label-count and entropy budget enforced by the DNS prober, which is
// unchanged.
var queryNameLabelRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$`)

func NormalizeHost(h string) (string, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", &DenyError{Category: DenyMalformed, Reason: "empty hostname"}
	}
	h = strings.TrimSuffix(h, ".")
	if len(h) > 253 {
		return "", &DenyError{Category: DenyMalformed, Reason: "hostname exceeds 253 characters"}
	}
	if hasForbiddenHostByte(h) {
		return "", &DenyError{Category: DenyMalformed, Reason: "hostname contains forbidden characters"}
	}
	h = strings.ToLower(h)
	if !hostnameLabelRe.MatchString(h) {
		return "", &DenyError{Category: DenyMalformed, Reason: "hostname does not match DNS label syntax"}
	}
	if !strings.Contains(h, ".") {
		return "", &DenyError{Category: DenyMalformed, Reason: "unqualified hostname not permitted"}
	}
	return h, nil
}

// NormalizeQueryName is NormalizeHost for a DNS query name: same trimming,
// same length cap, same forbidden bytes, same rejection of unqualified
// names — only the label alphabet differs, admitting the underscore.
//
// It is deliberately a separate entry point rather than a flag on
// NormalizeHost. A name that clears this function must never be dialled:
// it names a record to ask about, not a host to connect to. Guard.Authorize
// keeps using NormalizeHost, so an underscored name cannot reach the
// dialer even when a policy allow-lists it.
func NormalizeQueryName(h string) (string, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", &DenyError{Category: DenyMalformed, Reason: "empty query name"}
	}
	h = strings.TrimSuffix(h, ".")
	if len(h) > 253 {
		return "", &DenyError{Category: DenyMalformed, Reason: "query name exceeds 253 characters"}
	}
	if hasForbiddenHostByte(h) {
		return "", &DenyError{Category: DenyMalformed, Reason: "query name contains forbidden characters"}
	}
	h = strings.ToLower(h)
	if !queryNameLabelRe.MatchString(h) {
		return "", &DenyError{Category: DenyMalformed, Reason: "query name does not match DNS label syntax"}
	}
	if !strings.Contains(h, ".") {
		return "", &DenyError{Category: DenyMalformed, Reason: "unqualified query name not permitted"}
	}
	return h, nil
}

func hasForbiddenHostByte(s string) bool {
	for _, r := range s {
		switch {
		case r == 0:
			return true
		case r < 0x20:
			return true
		case r == 0x7f:
			return true
		case unicode.IsSpace(r):
			return true
		case r == '/' || r == '\\' || r == '?' || r == '#' || r == '@' ||
			r == ':' || r == '[' || r == ']' || r == ',' || r == ';':
			return true
		}
	}
	return false
}

// ValidateIPLiteral rejects non-canonical IP encodings (decimal integer,
// octal, hex, short forms). The strict netip.ParseAddr is applied afterwards.
func ValidateIPLiteral(s string) error {
	if s == "" {
		return errors.New("empty IP literal")
	}
	for _, r := range s {
		switch r {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'.', ':', 'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F':
		default:
			return fmt.Errorf("invalid IP literal %q: non-canonical encoding", s)
		}
	}
	return nil
}
