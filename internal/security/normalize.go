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
