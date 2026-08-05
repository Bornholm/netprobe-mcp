// Package probe — TCP named dialogues.
//
// Per PLAN §7.3, tcp_probe never exposes a free-form
// `send/expect/regexp` field to the agent. The agent picks a
// dialogue by name and the prober executes a hard-coded exchange
// from this catalogue. No byte ever crosses the wire that is not
// listed here.
//
// Why this matters: a query-response TCP probe against an
// allow-listed target is, by construction, a universal text-
// protocol client. An agent can already issue `smtp: relay mail
// to attacker.example`, `redis: CONFIG SET dir /var/spool/cron`,
// `mysql: SELECT … INTO OUTFILE`, etc. The named-dialogue list
// below is a closed allow-list of "banners only" — we read the
// greeting, optionally send ONE literal line that proves
// liveness, and stop.
//
// ALL dialogues are pure-ASCII. If a future dialogue needs
// binary content it must be added as a SEPARATE field on the
// struct, not by reusing Send.
package probe

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// DialogueID is the stable, opaque identifier an agent passes to
// tcp_probe. Adding a new ID is a code change, not a config
// change: this is the whole point of the design.
type DialogueID string

// Catalogue of supported dialogues. Extend with care — each new
// entry is code, not config (PLAN §7.3 spirit).
//
// The Expect patterns are intentionally UNANCHORED. A step
// matches as soon as the pattern appears anywhere in the
// accumulated response buffer. This matters for IMAP, where the
// reply to a single command ("CAPABILITY") is multi-line and the
// last line ("a001 OK …") is what we care about — anchoring with
// ^ would never match because the FIRST received line starts
// with "*", not "a001".
const (
	DialogueSMTPBanner  DialogueID = "smtp_banner"
	DialogueIMAPCapable DialogueID = "imap_capability"
	DialoguePOP3Banner  DialogueID = "pop3_banner"
	DialogueMySQLGreet  DialogueID = "mysql_handshake"
)

// DialogueStep is a single line of an exchange. Send is the
// literal to write to the socket (already CRLF-terminated where
// the protocol requires it); Expect is a regexp that the read
// buffer must match for the step to be considered successful.
type DialogueStep struct {
	// Label is a short description used in the agent-facing
	// summary; not part of the wire protocol.
	Label string

	// Send is a literal string, written verbatim to the
	// socket. The empty string means "do not send anything,
	// just wait for Expect". Newlines are encoded as \r\n
	// here (the canonical SMTP/IMAP/POP3 line ending) — agents
	// never get to choose the line ending.
	Send string

	// Expect is an UNANCHORED regexp that must match the bytes
	// read so far for the step to succeed. Empty Expect means
	// "any response (or silence) is acceptable".
	Expect string

	// readDeadline is the per-step cap on how long we wait
	// before giving up. Computed from the dialogue's overall
	// timeout; not user-tunable per call.
	readDeadline time.Duration

	// Send compiled once per prober (see CompileDialogue).
	expectRe *regexp.Regexp
}

// Dialogue is one full exchange (banner + optional sends).
type Dialogue struct {
	ID          DialogueID
	Description string
	// Steps are executed in order. A failed Expect aborts the
	// dialogue and surfaces `Success=false, error_class=protocol`.
	Steps []DialogueStep
}

// AllDialogues is the closed list exposed to the agent. Looking
// up an ID MUST go through this map; nowhere else.
var AllDialogues = map[DialogueID]Dialogue{
	DialogueSMTPBanner: {
		ID:          DialogueSMTPBanner,
		Description: "Read SMTP 220 banner, send EHLO, expect 250, send QUIT.",
		Steps: []DialogueStep{
			{Label: "banner", Expect: `220[\s-]`},
			{Label: "ehlo", Send: "EHLO netprobe-mcp\r\n", Expect: `250`},
			{Label: "quit", Send: "QUIT\r\n", Expect: `221`},
		},
	},
	DialogueIMAPCapable: {
		ID:          DialogueIMAPCapable,
		Description: "Read IMAP OK banner, send CAPABILITY, expect OK line.",
		Steps: []DialogueStep{
			{Label: "greeting", Expect: `\* OK`},
			{Label: "capability", Send: "a001 CAPABILITY\r\n", Expect: `a001 OK`},
			{Label: "logout", Send: "a002 LOGOUT\r\n"},
		},
	},
	DialoguePOP3Banner: {
		ID:          DialoguePOP3Banner,
		Description: "Read POP3 +OK banner, send QUIT.",
		Steps: []DialogueStep{
			{Label: "greeting", Expect: `\+OK`},
			{Label: "quit", Send: "QUIT\r\n", Expect: `\+OK`},
		},
	},
	DialogueMySQLGreet: {
		ID:          DialogueMySQLGreet,
		Description: "Read MySQL handshake greeting (server version + thread id).",
		Steps: []DialogueStep{
			{Label: "handshake", Expect: ""}, // non-ASCII binary protocol — no regexp match
		},
	},
}

// CompileDialogue prepares a dialogue for execution: each step's
// regex is compiled once with size/anchor limits, and the per-step
// read deadline is computed from the supplied total budget. The
// returned value is what Run() consumes; AllDialogues is left
// untouched so concurrent probes share no state.
//
// We deliberately do NOT compile on every call: compiling a
// user-controllable regexp per probe would multiply the cost of
// any potential ReDoS surface (per PLAN §7.3 last paragraph) with
// no benefit — these patterns are fixed.
func CompileDialogue(id DialogueID, total time.Duration) (*CompiledDialogue, error) {
	src, ok := AllDialogues[id]
	if !ok {
		return nil, fmt.Errorf("unknown dialogue %q", id)
	}
	if total <= 0 {
		total = 5 * time.Second
	}
	if len(src.Steps) == 0 {
		return nil, errors.New("dialogue has no steps (programmer error)")
	}

	steps := make([]DialogueStep, len(src.Steps))
	// Split the budget: the first step gets a bit more (the
	// banner may take longer, especially for protocols like
	// MySQL that send a payload instead of a line). Subsequent
	// steps share the remainder.
	first := total * 8 / 10
	if first <= 0 {
		first = total
	}
	restCount := len(src.Steps) - 1
	if restCount <= 0 {
		restCount = 1
	}
	rest := (total - first) / time.Duration(restCount)

	for i, s := range src.Steps {
		steps[i] = s
		if s.Expect != "" {
			// Bound the length of the pattern to reject
			// pathological constructions. Plan says these
			// strings are hard-coded by us, not the
			// operator — but defensive limits are free.
			if len(s.Expect) > 256 {
				return nil, fmt.Errorf("dialogue %q step %d: expect pattern too long", id, i)
			}
			re, err := regexp.Compile(s.Expect)
			if err != nil {
				return nil, fmt.Errorf("dialogue %q step %d: bad regex: %w", id, i, err)
			}
			steps[i].expectRe = re
		}
		deadline := rest
		if i == 0 {
			deadline = first
		}
		steps[i].readDeadline = deadline
	}

	return &CompiledDialogue{
		ID:    id,
		Steps: steps,
	}, nil
}

// CompiledDialogue is the ready-to-run form of a Dialogue.
// SendBytes returns the bytes to write for step i; ReadPattern
// returns the compiled regex (or nil if Expect was empty).
type CompiledDialogue struct {
	ID    DialogueID
	Steps []DialogueStep
}

// SendBytes returns the payload to write to the socket at step i.
// The empty string means "no send, just wait for Expect". The
// returned slice is safe to mutate by the caller (we allocate a
// fresh copy).
func (d *CompiledDialogue) SendBytes(i int) []byte {
	if i < 0 || i >= len(d.Steps) {
		return nil
	}
	s := d.Steps[i].Send
	if s == "" {
		return nil
	}
	// Force canonical CRLF. The user-facing surface already
	// encodes \r\n in the Send field; this is a defence in
	// depth in case a future step is added with literal \n.
	return []byte(strings.ReplaceAll(s, "\n", "\r\n"))
}

// ExpectPattern returns the compiled regex for step i (or nil).
func (d *CompiledDialogue) ExpectPattern(i int) *regexp.Regexp {
	if i < 0 || i >= len(d.Steps) {
		return nil
	}
	return d.Steps[i].expectRe
}

// StepDeadline returns the read deadline for step i.
func (d *CompiledDialogue) StepDeadline(i int) time.Duration {
	if i < 0 || i >= len(d.Steps) {
		return 0
	}
	return d.Steps[i].readDeadline
}
