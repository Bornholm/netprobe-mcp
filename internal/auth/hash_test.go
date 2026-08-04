package auth

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestHashToken(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"simple", "hunter2"},
		{"unicode", "pässwörd"},
		{"long", strings.Repeat("a", 4096)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := HashToken(tc.token)
			if len(got) != 64 {
				t.Fatalf("hash length = %d, want 64", len(got))
			}
			want := fmt.Sprintf("%x", sha256.Sum256([]byte(tc.token)))
			if got != want {
				t.Fatalf("HashToken(%q) = %q, want %q", tc.token, got, want)
			}
		})
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	a := HashToken("netprobe-token")
	b := HashToken("netprobe-token")
	if a != b {
		t.Fatalf("HashToken not deterministic: %q vs %q", a, b)
	}
	c := HashToken("netprobe-token-different")
	if a == c {
		t.Fatalf("distinct tokens produced identical hashes")
	}
}

func TestHashToken_NoTrailingNewline(t *testing.T) {
	// Operators paste the output directly into the YAML policy.
	// A trailing newline would silently break authentication.
	got := HashToken("any-token")
	if strings.ContainsAny(got, " \t\r\n") {
		t.Fatalf("hash contains whitespace: %q", got)
	}
}
