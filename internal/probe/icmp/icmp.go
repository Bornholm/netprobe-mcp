// Package icmp implements the icmp_probe tool.
//
// ICMP is the probe with the highest operational risk on Linux:
// raw sockets require CAP_NET_RAW (root or capability). The
// non-privileged alternative is a UDP datagram socket, which the
// kernel rewrites with ICMP semantics when net.ipv4.ping_group_range
// covers the process GID. Both modes are supported, and the choice
// is made at boot, once, by DetectCapability().
//
// Per PLAN.md §7.4:
//   - Preferred: UDP unprivileged socket (no extra capability needed).
//   - Acceptable: raw socket with CAP_NET_RAW.
//   - Never: setuid root.
//
// All sent packets carry a 16-byte random "magic" prefix so the
// demultiplexer can reject foreign ICMP packets that happen to share
// the same ID/sequence numbers (a known concern with raw sockets).
package icmp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/probe"
	"github.com/bornholm/netprobe-mcp/internal/security"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Mode describes how the probe actually sends its packets.
type Mode string

const (
	ModeUnprivileged Mode = "unprivileged_udp" // SOCK_DGRAM, no capability
	ModeRaw          Mode = "raw_socket"       // SOCK_RAW, requires CAP_NET_RAW
	ModeUnavailable  Mode = "unavailable"      // neither mode works
)

// Capability is the result of one-shot detection at boot.
type Capability struct {
	Mode Mode
	// Reason, when Mode is ModeUnavailable, documents why.
	Reason string
}

// DetectCapability tries the unprivileged mode first, then the raw
// socket. It MUST be called once at boot: subsequent calls keep
// opening sockets. The function is cheap enough for tests though.
func DetectCapability() Capability {
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		_ = c.Close()
		return Capability{Mode: ModeUnprivileged}
	}
	if c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		_ = c.Close()
		return Capability{Mode: ModeRaw}
	}
	return Capability{
		Mode:   ModeUnavailable,
		Reason: "neither unprivileged ICMP (net.ipv4.ping_group_range) nor CAP_NET_RAW available",
	}
}

// Options is the agent-facing input for icmp_probe.
type Options struct {
	Host         string `json:"host" jsonschema:"hostname or IP to ping"`
	Count        int    `json:"count,omitempty" jsonschema:"echo requests to send (1-10)"`
	IntervalMs   int    `json:"interval_ms,omitempty" jsonschema:"delay between requests, min 200ms"`
	TimeoutMs    int    `json:"timeout_ms,omitempty"`
	PayloadSize  int    `json:"payload_size,omitempty" jsonschema:"payload bytes (0-1400)"`
	DontFragment bool   `json:"dont_fragment,omitempty"`
}

// Reply is a single observed response.
type Reply struct {
	From  netip.Addr `json:"from"`
	RTTMs float64    `json:"rtt_ms"`
	Bytes int        `json:"bytes"`
	Type  string     `json:"type"`
}

// Result is the structured output. Marshals to JSON for the LLM.
type Result struct {
	probe.Result
	Mode            string  `json:"mode"`
	PacketsSent     int     `json:"packets_sent"`
	PacketsReceived int     `json:"packets_received"`
	PacketLossPct   float64 `json:"packet_loss_pct"`
	MinRTTMs        float64 `json:"min_rtt_ms,omitempty"`
	AvgRTTMs        float64 `json:"avg_rtt_ms,omitempty"`
	MaxRTTMs        float64 `json:"max_rtt_ms,omitempty"`
	Replies         []Reply `json:"replies,omitempty"`
}

// Prober performs an ICMP echo (ping) sequence against a SafeTarget.
// The constructor is given a Mode chosen at boot by
// DetectCapability; the prober refuses to send if the mode is
// ModeUnavailable.
//
// Hard caps (10 packets max, 200ms minimum interval, 1400-byte
// payload ceiling) are applied independently of the per-call
// configuration so a misconfigured policy cannot widen them.
type Prober struct {
	mode        Mode
	timeout     time.Duration
	maxCount    int
	maxBytes    int
	minInterval time.Duration
}

// NewProber builds an ICMP prober. mode is typically the value
// returned by DetectCapability at boot; passing ModeUnavailable here
// causes every Run() call to fail with a structured error.
//
// maxCount, minInterval and maxBytes are the operator-tunable
// ceilings. They default to the PLAN §7.4 values (10, 200ms, 1400)
// when the supplied configuration leaves the field zero or
// negative, but the hard caps in Run() still apply on top.
func NewProber(mode Mode, defaultTimeout time.Duration, maxCount int, minInterval time.Duration, maxBytes int) *Prober {
	if maxCount <= 0 {
		maxCount = 10
	}
	if maxCount > 10 {
		maxCount = 10
	}
	if minInterval <= 0 {
		minInterval = 200 * time.Millisecond
	}
	if minInterval < 200*time.Millisecond {
		minInterval = 200 * time.Millisecond
	}
	if maxBytes <= 0 {
		maxBytes = 1400
	}
	if maxBytes > 1400 {
		maxBytes = 1400
	}
	return &Prober{
		mode:        mode,
		timeout:     defaultTimeout,
		maxCount:    maxCount,
		minInterval: minInterval,
		maxBytes:    maxBytes,
	}
}

// Mode returns the operating mode the prober was constructed for.
// Useful for the MCP layer to decide whether to expose the tool at
// all (PLAN.md §9.3).
func (p *Prober) Mode() Mode { return p.mode }

// Validate checks the agent-supplied options.
func (p *Prober) Validate(opts *Options) error {
	if opts == nil {
		return errors.New("missing options")
	}
	if opts.Host == "" {
		return errors.New("host is required")
	}
	if opts.Count <= 0 {
		opts.Count = 3
	}
	if opts.Count > p.maxCount {
		opts.Count = p.maxCount
	}
	if opts.IntervalMs <= 0 {
		opts.IntervalMs = int(p.minInterval / time.Millisecond)
	}
	if time.Duration(opts.IntervalMs)*time.Millisecond < p.minInterval {
		// PLAN §7.4: keep the configured floor (200ms by default).
		opts.IntervalMs = int(p.minInterval / time.Millisecond)
	}
	if opts.TimeoutMs <= 0 {
		opts.TimeoutMs = int(p.timeout / time.Millisecond)
	}
	if opts.PayloadSize < 0 || opts.PayloadSize > p.maxBytes {
		return fmt.Errorf("payload_size must be in 0..%d", p.maxBytes)
	}
	return nil
}

// magic is the 16-byte prefix every ICMP probe carries. Random per
// process so an attacker on the wire cannot forge responses that
// match our ID/Seq and steal our slot.
var magic []byte

func init() {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// Falling back to PID-derived magic: still per-process, just
		// less random. This should not happen on any platform Go
		// supports.
		pid := uint32(os.Getpid())
		for i := 0; i < 16; i += 4 {
			binary.BigEndian.PutUint32(buf[i:], pid)
		}
	}
	magic = buf
}

// multiplexer demultiplexes incoming ICMP packets among pending
// probes. There is one shared raw socket per process; unprivileged
// sockets are independent, so the multiplexer is only used in raw
// mode.
type multiplexer struct {
	mu      sync.Mutex
	pending map[int]chan *Reply
	nextID  atomic.Uint32
}

func newMultiplexer() *multiplexer {
	return &multiplexer{pending: make(map[int]chan *Reply)}
}

func (m *multiplexer) register() (id int, ch chan *Reply) {
	id = int(m.nextID.Add(1) & 0xffff)
	ch = make(chan *Reply, 1)
	m.mu.Lock()
	m.pending[id] = ch
	m.mu.Unlock()
	return id, ch
}

func (m *multiplexer) unregister(id int) {
	m.mu.Lock()
	delete(m.pending, id)
	m.mu.Unlock()
}

func (m *multiplexer) deliver(r *inboundReply) {
	m.mu.Lock()
	ch, ok := m.pending[r.id]
	m.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- &r.Reply:
	default:
	}
}

// Reply embeds an identifier so the multiplexer can route.
type inboundReply struct {
	Reply
	id int
}

// globalMux is process-wide so the multiplexer survives the prober
// instance lifetime. It is started lazily on the first raw-mode use.
var (
	globalMux     *multiplexer
	globalMuxOnce sync.Once
)

func getMultiplexer() *multiplexer {
	globalMuxOnce.Do(func() { globalMux = newMultiplexer() })
	return globalMux
}

// startMultiplexerReader spins up a goroutine that reads from the
// shared raw socket and feeds replies into the multiplexer. Safe to
// call repeatedly; only the first call starts the reader.
func startMultiplexerReader(ctx context.Context) error {
	if globalMux == nil {
		globalMux = newMultiplexer()
	}
	if readerStarted.Swap(true) {
		return nil
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		readerStarted.Store(false)
		return fmt.Errorf("multiplexer raw socket: %w", err)
	}
	go func() {
		defer conn.Close()
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			msg, err := icmp.ParseMessage(ianaProtocolICMP, buf[:n])
			if err != nil {
				continue
			}
			echo, ok := msg.Body.(*icmp.Echo)
			if !ok {
				continue
			}
			if msg.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			if !bytes.HasPrefix(echo.Data, magic) {
				continue
			}
			addr, ok := peer.(*net.IPAddr)
			if !ok {
				continue
			}
			r := &inboundReply{
				id: echo.ID,
				Reply: Reply{
					From:  netip.MustParseAddr(addr.IP.String()),
					Bytes: n,
					Type:  "echo_reply",
				},
			}
			globalMux.deliver(r)
		}
	}()
	return nil
}

var readerStarted atomic.Bool

// ianaProtocolICMP mirrors the constant from x/net/icmp — duplicated
// here to avoid importing the internal "iana" package.
const ianaProtocolICMP = 1

// Run executes the probe. target is the validated SafeTarget; the
// probe never re-resolves or re-validates the host.
func (p *Prober) Run(ctx context.Context, target *security.SafeTarget, opts Options) (*Result, error) {
	if p.mode == ModeUnavailable {
		return nil, errors.New("icmp_probe is unavailable: no ICMP capability at boot")
	}
	if err := p.Validate(&opts); err != nil {
		return nil, err
	}

	start := probe.Now()
	dst := &net.IPAddr{IP: net.IP(target.IP.AsSlice())}

	if p.mode == ModeRaw {
		if err := startMultiplexerReader(ctx); err != nil {
			return nil, err
		}
	}

	// One socket per call: in unprivileged mode each socket has a
	// unique kernel-assigned ID, so we don't need the multiplexer
	// at all. In raw mode we share the global raw socket and rely
	// on the multiplexer to demultiplex.
	var conn *icmp.PacketConn
	if p.mode == ModeUnprivileged {
		c, err := icmp.ListenPacket("udp4", "0.0.0.0")
		if err != nil {
			return nil, fmt.Errorf("icmp listen: %w", err)
		}
		conn = c
		defer conn.Close()
	}

	interval := time.Duration(opts.IntervalMs) * time.Millisecond
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	payload := buildPayload(opts.PayloadSize)

	result := &Result{
		Mode:        string(p.mode),
		PacketsSent: opts.Count,
	}
	sent := 0
	received := 0
	var minRtt, maxRtt, sumRtt float64

	for seq := 0; seq < opts.Count; seq++ {
		if ctx.Err() != nil {
			break
		}
		// Build the echo message.
		echo := &icmp.Echo{
			ID:   0, // overwritten in raw mode
			Seq:  seq + 1,
			Data: append(append([]byte{}, magic...), payload...),
		}
		msg := &icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: echo,
		}
		if p.mode == ModeRaw {
			echo.ID = int(getMultiplexer().nextID.Add(1) & 0xffff)
		}
		bin, err := msg.Marshal(nil)
		if err != nil {
			return nil, err
		}
		// Register slot in the multiplexer BEFORE writing so we
		// never miss a reply that races the send.
		var (
			muxID int
			reply chan *Reply
		)
		if p.mode == ModeRaw {
			muxID = echo.ID
			reply = make(chan *Reply, 1)
			getMultiplexer().mu.Lock()
			getMultiplexer().pending[muxID] = reply
			getMultiplexer().mu.Unlock()
			defer getMultiplexer().unregister(muxID)
		}

		writtenAt := probe.Now()
		if _, err := conn.WriteTo(bin, dst); err != nil {
			if p.mode == ModeRaw {
				getMultiplexer().unregister(muxID)
			}
			return nil, err
		}
		sent++

		// Wait for a reply (raw) or read until timeout (unprivileged).
		rttDeadline := writtenAt.Add(timeout)
		var got *Reply
		if p.mode == ModeRaw {
			select {
			case got = <-reply:
			case <-time.After(timeout):
				got = nil
			case <-ctx.Done():
				got = nil
			}
		} else {
			// Unprivileged mode: read from our own socket.
			_ = conn.SetReadDeadline(rttDeadline)
			rb := make([]byte, 1500)
			n, peer, rerr := conn.ReadFrom(rb)
			if rerr == nil {
				m, perr := icmp.ParseMessage(ianaProtocolICMP, rb[:n])
				if perr == nil && m.Type == ipv4.ICMPTypeEchoReply {
					if e, ok := m.Body.(*icmp.Echo); ok {
						addr, _ := peer.(*net.IPAddr)
						got = &Reply{
							From:  netip.MustParseAddr(addr.IP.String()),
							Bytes: n,
							Type:  "echo_reply",
						}
						_ = e
					}
				}
			}
		}
		if got != nil {
			rtt := probe.Now().Sub(writtenAt)
			got.RTTMs = float64(rtt.Microseconds()) / 1000.0
			received++
			if minRtt == 0 || rtt.Seconds() < minRtt {
				minRtt = rtt.Seconds()
			}
			if rtt.Seconds() > maxRtt {
				maxRtt = rtt.Seconds()
			}
			sumRtt += rtt.Seconds()
			result.Replies = append(result.Replies, *got)
		}

		// Sleep until the next packet, unless this was the last.
		if seq < opts.Count-1 {
			select {
			case <-time.After(interval):
			case <-ctx.Done():
			}
		}
	}

	result.PacketsSent = sent
	result.PacketsReceived = received
	if sent > 0 {
		result.PacketLossPct = float64(sent-received) / float64(sent) * 100.0
	}
	if received > 0 {
		result.MinRTTMs = minRtt * 1000.0
		result.MaxRTTMs = maxRtt * 1000.0
		result.AvgRTTMs = (sumRtt / float64(received)) * 1000.0
	}
	result.Success = received > 0
	result.Probe = "icmp_probe"
	result.Target = probe.Target{
		Requested:  opts.Host,
		Hostname:   target.Hostname,
		ResolvedIP: target.IP.String(),
		Port:       0,
		Scheme:     "icmp",
	}
	result.DurationMs = float64(probe.Now().Sub(start).Microseconds()) / 1000.0
	result.Timings.TotalMs = result.DurationMs
	return result, nil
}

func buildPayload(size int) []byte {
	if size <= 0 {
		return nil
	}
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}
