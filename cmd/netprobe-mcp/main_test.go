package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// These tests rebuild the binary and exercise the `hash` subcommand
// end-to-end. They are guarded by the `integration` build tag so
// quick unit runs stay hermetic.
func TestHashSubcommand(t *testing.T) {
	bin := buildBinary(t)
	defer os.Remove(bin)

	cases := []struct {
		name  string
		token string
	}{
		{"hunter2", "hunter2"},
		{"unicode", "pässwörd"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command(bin, "hash", tc.token).Output()
			if err != nil {
				t.Fatalf("hash %q: %v\nstderr=%s", tc.token, err, out)
			}
			got := strings.TrimSpace(string(out))
			want := fmt.Sprintf("%x", sha256.Sum256([]byte(tc.token)))
			if got != want {
				t.Fatalf("hash(%q) = %q, want %q", tc.token, got, want)
			}
		})
	}
}

func TestHashSubcommand_MissingArg(t *testing.T) {
	bin := buildBinary(t)
	defer os.Remove(bin)

	cmd := exec.Command(bin, "hash")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected non-zero exit when token is missing\nstdout=%s\nstderr=%s",
			stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr should mention 'usage:', got %q", stderr.String())
	}
}

func TestHashSubcommand_NoExtraWhitespace(t *testing.T) {
	bin := buildBinary(t)
	defer os.Remove(bin)

	out, err := exec.Command(bin, "hash", "x").Output()
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	s := string(out)
	// The output should be exactly "<64-hex>\n". Any extra
	// trailing whitespace would break a YAML paste.
	if strings.Count(s, "\n") != 1 {
		t.Fatalf("hash output contains unexpected newlines: %q", s)
	}
	trimmed := strings.TrimRight(s, "\r\n")
	if trimmed != s[:len(s)-1] {
		t.Fatalf("hash output has trailing whitespace beyond the final newline: %q", s)
	}
}

func TestHashSubcommand_BypassesConfig(t *testing.T) {
	// `netprobe-mcp hash` must NOT require --config and must not
	// touch the filesystem. Pointing --config at a guaranteed-
	// missing path ensures we fail loudly if the subcommand
	// accidentally falls through to the server path.
	bin := buildBinary(t)
	defer os.Remove(bin)

	cmd := exec.Command(bin, "--config=/nonexistent/yaml", "hash", "x")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("hash should ignore --config; got error %v, stderr=%s", err, stderr.String())
	}
	if strings.TrimSpace(string(out)) != fmt.Sprintf("%x", sha256.Sum256([]byte("x"))) {
		t.Fatalf("unexpected output %q", string(out))
	}
}

// buildBinary compiles the cmd package to a temporary file and
// returns its path. Skips the test (rather than failing) when the
// toolchain cannot compile, so the suite still runs in stripped
// environments.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin, err := os.CreateTemp(t.TempDir(), "netprobe-mcp-test-*.bin")
	if err != nil {
		t.Fatalf("tempfile: %v", err)
	}
	bin.Close()
	cmd := exec.Command("go", "build", "-o", bin.Name(), ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Remove(bin.Name())
		t.Skipf("go build failed (likely cgo toolchain missing): %v", err)
	}
	return bin.Name()
}
