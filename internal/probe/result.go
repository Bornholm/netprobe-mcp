package probe

import (
	"time"
)

// Result is the structured, agent-facing output of any probe.
// IsError / Error are only set when the tool itself failed (validation,
// authorization, internal error). Network-level failures against the target
// are NOT tool errors: they are observations and go in Success=false with a
// sanitized Error / ErrorClass.
type Result struct {
	Success    bool    `json:"success"`
	Probe      string  `json:"probe"`
	Target     Target  `json:"target"`
	DurationMs float64 `json:"duration_ms"`
	Timings    Timings `json:"timings"`
	Error      string  `json:"error,omitempty"`
	ErrorClass string  `json:"error_class,omitempty"`

	HTTP *HTTPResult `json:"http,omitempty"`
	TCP  *TCPResult  `json:"tcp,omitempty"`
	DNS  *DNSResult  `json:"dns,omitempty"`
}

type Target struct {
	Requested  string `json:"requested"`
	Hostname   string `json:"hostname"`
	ResolvedIP string `json:"resolved_ip"`
	Port       uint16 `json:"port"`
	Scheme     string `json:"scheme,omitempty"`
}

type Timings struct {
	DNSMs      float64 `json:"dns_ms,omitempty"`
	ConnectMs  float64 `json:"connect_ms"`
	TLSMs      float64 `json:"tls_ms,omitempty"`
	ProcessMs  float64 `json:"process_ms,omitempty"`
	TransferMs float64 `json:"transfer_ms,omitempty"`
	TotalMs    float64 `json:"total_ms"`
}

type TCPResult struct {
	Connected       bool   `json:"connected"`
	RemoteAddr      string `json:"remote_addr"`
	Banner          string `json:"banner,omitempty"`
	BannerBytes     int64  `json:"banner_bytes"`
	BannerTruncated bool   `json:"banner_truncated"`
	// Dialogue is the name of the named dialogue executed by
	// this probe, when opts.Dialogue is set. The Steps field
	// then carries the per-step transcript.
	Dialogue string          `json:"dialogue,omitempty"`
	Steps    []TCPStepResult `json:"steps,omitempty"`
}

// TCPStepResult records one step of a named dialogue. The
// fields are deliberately minimal: the agent gets the labels and
// a short transcript excerpt, NOT the raw bytes (which can be
// a binary handshake for mysql_handshake, see PLAN §7.3).
type TCPStepResult struct {
	Label   string `json:"label"`
	Sent    string `json:"sent,omitempty"`
	Matched bool   `json:"matched"`
	Excerpt string `json:"excerpt,omitempty"`
}

// Now is overridable in tests.
var Now = time.Now
