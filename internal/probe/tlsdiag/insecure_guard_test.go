package tlsdiag

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInsecureSkipVerifyIsConfined ensures that the
// InsecureSkipVerify=true setting only appears in the tlsdiag
// active-phase modules (protocols.go, ciphers.go, sni.go). Anywhere else, a
// future contributor adding `InsecureSkipVerify: true` is a
// regression: a tool that diagnoses TLS security must not silently
// bypass certificate verification.
//
// Each module is justified:
//   - protocols.go: enumerating TLS versions requires ignoring the
//     validity of the certificate (the goal is "did the server
//     negotiate this version", not "is the cert valid").
//   - ciphers.go: same rationale for cipher suite negotiation.
//   - sni.go: a no-SNI handshake by definition produces a cert
//     whose name does not match ServerName; the comparison is on
//     the cert bytes themselves, not their validity.
func TestInsecureSkipVerifyIsConfined(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"protocols.go": true,
		"ciphers.go":   true,
		"sni.go":       true,
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(src, []byte("InsecureSkipVerify: true")) {
			rel, _ := filepath.Rel(root, path)
			if !allowed[rel] {
				t.Errorf("InsecureSkipVerify:true found in %s (forbidden)", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestNoActivePhaseMarkers ensures that the v1 "active phase
// pending" markers have been removed. Each marker was a comment
// placed where a future active phase would land; its presence in
// the codebase indicates a phase was planned but never implemented.
func TestNoActivePhaseMarkers(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	markers := []string{
		"// ACTIVE: probe_sni_behaviour",
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range markers {
			if bytes.Contains(src, []byte(m)) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("active phase marker %q present in %s", m, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
