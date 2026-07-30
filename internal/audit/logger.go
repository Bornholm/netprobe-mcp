package audit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Event is one immutable record per tool call.
type Event struct {
	Timestamp       time.Time `json:"ts"`
	EventID         string    `json:"event_id"`
	SessionID       string    `json:"session_id,omitempty"`
	Tool            string    `json:"tool"`
	RequestedTarget string    `json:"requested_target,omitempty"`
	ResolvedAddr    string    `json:"resolved_addr,omitempty"`
	ResolvedPort    uint16    `json:"resolved_port,omitempty"`
	Decision        string    `json:"decision"` // allowed | denied
	DenyReason      string    `json:"deny_reason,omitempty"`
	MatchedRule     string    `json:"matched_rule,omitempty"`
	Outcome         string    `json:"outcome"` // success | probe_failure | policy_denied | internal_error
	DurationMs      float64   `json:"duration_ms"`

	// OutboundURLs records every URL the diagnostic or probe emitted a
	// request to at the behest of the target. This is the only
	// observable trail of secondary SSRF channels (AIA chasing,
	// direct OCSP queries): the URL is taken from the certificate, so
	// it is attacker-controlled. Surfacing it in the audit log makes
	// post-incident analysis possible. See PLAN.md §11.1.
	OutboundURLs []OutboundURLEvent `json:"outbound_urls,omitempty"`

	// Findings lists the stable IDs of every TLS finding emitted by
	// the call. Operators alerting on a specific CVE-class finding
	// (e.g. TLS_MUST_STAPLE_WITHOUT_STAPLE) can correlate this field
	// without having to parse the structured response.
	Findings []string `json:"findings,omitempty"`
}

// OutboundURLEvent describes one secondary HTTP request emitted by a
// probe. Purpose makes it possible to distinguish an AIA fetch from
// an OCSP query in the audit log.
type OutboundURLEvent struct {
	URL       string `json:"url"`
	Purpose   string `json:"purpose,omitempty"`
	Outcome   string `json:"outcome,omitempty"` // success | denied | error
	BytesRead int64  `json:"bytes_read,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

const (
	OutcomeSuccess      = "success"
	OutcomeProbeFailure = "probe_failure"
	OutcomeDenied       = "policy_denied"
	OutcomeInternal     = "internal_error"
)

type Config struct {
	Format string // "json" or "text"
	Output string // "stderr", "stdout", or "file:/path"
	Level  string
	// Writer, if non-nil, is used instead of the Output destination. Used by
	// tests that need to capture the audit stream into an in-memory buffer.
	Writer     io.Writer
	LogTargets bool
}

type Logger struct {
	underlying *slog.Logger
	mu         sync.Mutex
	ch         chan *Event
	dropped    atomic.Uint64
	stopped    chan struct{}
	wg         sync.WaitGroup
	logTargets bool
}

func New(cfg Config) (*Logger, error) {
	if cfg.Format == "" {
		cfg.Format = "json"
	}

	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	var w io.Writer
	if cfg.Writer != nil {
		w = cfg.Writer
	} else {
		switch cfg.Output {
		case "", "stderr":
			w = os.Stderr
		case "stdout":
			w = os.Stdout
		default:
			if strings.HasPrefix(cfg.Output, "file:") {
				path := strings.TrimPrefix(cfg.Output, "file:")
				f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
				if err != nil {
					return nil, err
				}
				w = f
			} else {
				w = os.Stderr
			}
		}
	}

	handlerOpts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch cfg.Format {
	case "json":
		handler = slog.NewJSONHandler(w, handlerOpts)
	default:
		handler = slog.NewTextHandler(w, handlerOpts)
	}

	l := &Logger{
		underlying: slog.New(handler).With(slog.String("component", "audit")),
		ch:         make(chan *Event, 256),
		stopped:    make(chan struct{}),
		logTargets: cfg.LogTargets,
	}
	l.wg.Add(1)
	go l.run()
	return l, nil
}

func (l *Logger) Emit(ev *Event) {
	if ev.EventID == "" {
		ev.EventID = uuid.NewString()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.Decision == "denied" {
		l.writeSync(ev)
		return
	}
	select {
	case l.ch <- ev:
	default:
		l.dropped.Add(1)
	}
}

func (l *Logger) writeSync(ev *Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	attrs := []slog.Attr{
		slog.String("event_id", ev.EventID),
		slog.Time("ts", ev.Timestamp),
		slog.String("session_id", ev.SessionID),
		slog.String("tool", ev.Tool),
		slog.String("decision", ev.Decision),
		slog.String("deny_reason", ev.DenyReason),
		slog.String("matched_rule", ev.MatchedRule),
		slog.String("outcome", ev.Outcome),
		slog.Float64("duration_ms", ev.DurationMs),
	}
	if l.logTargets {
		attrs = append(attrs,
			slog.String("requested_target", ev.RequestedTarget),
			slog.String("resolved_addr", ev.ResolvedAddr),
			slog.Int("resolved_port", int(ev.ResolvedPort)),
		)
	}
	if len(ev.OutboundURLs) > 0 {
		urls := make([]string, 0, len(ev.OutboundURLs))
		for _, u := range ev.OutboundURLs {
			entry := u.URL
			if u.Purpose != "" {
				entry = "[" + u.Purpose + "] " + entry
			}
			if u.Outcome != "" {
				entry += " (" + u.Outcome + ")"
			}
			urls = append(urls, entry)
		}
		attrs = append(attrs, slog.Any("outbound_urls", urls))
	}
	if len(ev.Findings) > 0 {
		attrs = append(attrs, slog.Any("findings", ev.Findings))
	}
	l.underlying.LogAttrs(context.Background(), slog.LevelInfo, "audit", attrs...)
}

func (l *Logger) run() {
	defer l.wg.Done()
	for {
		select {
		case ev := <-l.ch:
			l.writeSync(ev)
		case <-l.stopped:
			for {
				select {
				case ev := <-l.ch:
					l.writeSync(ev)
				default:
					return
				}
			}
		}
	}
}

func (l *Logger) Close() error {
	select {
	case <-l.stopped:
		return nil
	default:
		close(l.stopped)
	}
	l.wg.Wait()
	return nil
}

func (l *Logger) Dropped() uint64 { return l.dropped.Load() }

// MarshalJSON ensures a stable representation when events are serialized.
func (e *Event) MarshalJSON() ([]byte, error) {
	type alias Event
	return json.Marshal((*alias)(e))
}
