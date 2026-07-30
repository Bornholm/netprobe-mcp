// Tests for the cipher suite enumeration active phase.

package tlsdiag

import (
	"net/netip"
	"testing"

	"github.com/bornholm/netprobe-mcp/internal/security"
)

func TestProbeCipherSuites_Healthy(t *testing.T) {
	addr, pool, _ := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep := a.probeCipherSuites(testContext(t), tgt)
	if !rep.ForwardSecrecy {
		t.Errorf("expected ForwardSecrecy=true on default Go TLS server, got %+v", rep)
	}
	// The Go default TLS config still offers CBC+SHA1 and 3DES
	// suites; that is a separate finding from the probe itself.
	if rep.WeakNULL || rep.WeakRC4 || rep.WeakExport || rep.WeakAnon {
		t.Errorf("expected NULL/RC4/EXPORT/ANON suites to remain undetected, got %+v", rep)
	}
}

func TestProbeCipherSuites_RunsThroughRunOptionalPhases(t *testing.T) {
	addr, pool, _ := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep, err := a.Diagnose(tgt, DiagnoseOptions{ProbeCipherSuites: true})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if rep.CipherSuites == nil {
		t.Fatalf("expected CipherSuites to be populated when ProbeCipherSuites=true")
	}
	for _, s := range rep.ChecksSkipped {
		if s.Check == "TLS_CIPHER_SUITES_ENUM" {
			t.Errorf("expected TLS_CIPHER_SUITES_ENUM to be removed after run")
		}
	}
}

func TestProbeCipherSuites_NotEnabled(t *testing.T) {
	addr, pool, _ := startTLSServer(t)
	host, port := splitAddr(addr)
	tgt := &security.SafeTarget{
		Hostname: "localhost",
		IP:       netip.MustParseAddr(host),
		Port:     port,
		Scheme:   "tls",
	}
	a := analyzerStubWithDialer(t, pool)
	rep, err := a.Diagnose(tgt, DiagnoseOptions{})
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if rep.CipherSuites != nil {
		t.Errorf("expected CipherSuites=nil when ProbeCipherSuites=false")
	}
}

func TestCipherGroupSuites(t *testing.T) {
	// Each known group must return a non-empty slice (except the
	// explicitly unprobeable ones: rc4, null, export, anon). The
	// table is small and changes rarely; this test catches
	// regressions when constants are removed upstream.
	cases := []struct {
		id        string
		probeable bool
	}{
		{"fs", true},
		{"cbc_sha1", true},
		{"3des", true},
		{"rc4", false},
		{"null", false},
		{"export", false},
		{"anon", false},
	}
	for _, c := range cases {
		group, ok := cipherGroupByID(c.id)
		if !ok {
			t.Errorf("cipherGroupByID(%q): not found", c.id)
			continue
		}
		suites := cipherGroupSuites(group)
		if c.probeable && len(suites) == 0 {
			t.Errorf("group %q should be probeable", c.id)
		}
		if !c.probeable && len(suites) != 0 {
			t.Errorf("group %q should not be probeable, got %v", c.id, suites)
		}
	}
}

// cipherGroupByID is a small test helper.
func cipherGroupByID(id string) (cipherGroup, bool) {
	for _, g := range cipherGroups {
		if g.id == id {
			return g, true
		}
	}
	return cipherGroup{}, false
}
