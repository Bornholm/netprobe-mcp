# Security Model — netprobe-mcp

This document is the operator-facing counterpart of `PLAN.md` §1
(Threat Model) and §5 (Guard pipeline). It explains what an operator
must understand before deploying the server, what defences are in
place, what limitations are honest, and how to interpret the audit
log.

For the architecture overview, see `README.md`. For the
authoritative threat model and pipeline specification, see
`PLAN.md`. This document is intentionally shorter and operational.

## 1. What this server is

`netprobe-mcp` is a Model Context Protocol (MCP) server that lets
an LLM agent perform **read-only network probing** against a fixed,
operator-defined set of targets. The tools are:

- `tcp_probe` — open a TCP connection, optionally read a banner or
  run one of four hard-coded named dialogues (SMTP, IMAP, POP3,
  MySQL). The agent cannot send arbitrary bytes.
- `http_probe` — issue a single HTTP(S) request. Bodies are limited,
  sanitised, and opt-in. Redirects are re-authorised through the
  same Guard pipeline.
- `dns_probe` — issue a single DNS query against a server and
  QNAME that are both allow-listed.
- `icmp_probe` — send ICMP echo requests. Privileged mode is
  detected at boot; if absent, the tool is not registered.
- `grpc_probe` — issue a single `grpc.health.v1.Health/Check`. No
  arbitrary RPC, no reflection.
- `tls_diagnose` — passive TLS analysis: one handshake, one chain
  inspection, one OCSP read. Active phases (protocol enumeration,
  cipher probing, AIA chasing) are gated by configuration and
  default to off.

Every probe goes through the same pipeline: validate → allow-list
match → DNS resolution (pinned) → IP filter → rate limit → probe.
A failure at any step is reported as a `DenyError` with a typed
category (`target_not_allowed`, `ip_range_restricted`,
`rate_limited`, …) and a public message that never reveals
internal infrastructure.

## 2. Threat model

The server runs in a hostile environment: the input is, by
construction, attacker-controlled. A prompt injection in a page
read by the agent can become an arbitrary tool call.

| Threat                                          | Vector                                                                                          | Mitigation                                                                                                                       |
|-------------------------------------------------|-------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| **SSRF to cloud metadata**                      | `http_probe("http://169.254.169.254/latest/meta-data/iam/…")`                                     | RFC1918 + link-local + cloud-metadata bogons in `IPFilter`; deny-by-default allow-list; "downgrade" rule on redirects.            |
| **SSRF to internal network**                    | `tcp_probe("10.0.0.5", 6379)`                                                                    | Allow-list of destinations, ports, schemes, methods, paths. Loopback / RFC1918 / ULA denied by default.                          |
| **DNS rebinding / TOCTOU**                      | Allow-listed hostname resolves to `127.0.0.1` on the second lookup.                              | Resolution happens **once** per call; `SafeDialer.PinnedDialContext` ignores the destination argument and connects to the validated IP. |
| **Amplification / DoS outgoing**                | Agent loops over probes against a single target.                                                  | Five-level rate limit: session quota (absolute counter), per-tool, global, per-target (keyed token bucket), concurrency semaphore. |
| **Data exfiltration**                           | `http_probe` with crafted headers/body to a server under attacker control.                      | Allow-list of destinations; closed list of request header names; body opt-in only; bodies sanitised and truncated.               |
| **Port scanning**                               | Iteration over `tcp_probe(host, port)` across many ports.                                        | Allow-list restricts ports per rule; per-target rate limit.                                                                      |
| **Resource exhaustion**                         | Large responses, infinite redirect chains, slow upstreams.                                       | `io.LimitReader`, `MaxRedirects`, per-probe timeout bound by `probes.max_timeout`.                                              |
| **Protocol injection**                          | CRLF in headers, control bytes in hostnames.                                                     | Strict validation in `NormalizeHost` and `applyHeaders`.                                                                         |
| **ICMP privilege escalation**                   | ICMP needs raw sockets.                                                                         | Unprivileged UDP socket first (`net.ipv4.ping_group_range`), then `CAP_NET_RAW` capability, then unavailable.                  |
| **Error-driven internal reconnaissance**         | Verbose DNS / TLS errors leaking internal topology.                                              | Errors are categorised; the public message is sanitised; the raw cause stays in the audit log only.                            |
| **DNS rebinding inside TLS SNI**                | Agent connects to a hostname the IP filter allows but whose certificate is for a different name. | `HostnameMatches` check on the leaf; finding `TLS_HOSTNAME_MISMATCH` if it fails.                                                 |
| **AIA / OCSP SSRF**                             | AIA chasing or direct OCSP query issuing HTTP GET to an attacker-controlled URL in the certificate. | Off by default (`AllowAIAFetch=false`, `AllowOCSPQuery=false`); when on, requests go through `Guard.Authorize` with `Purpose=aia_fetch`/`ocsp_query`; separate allow-list rule required. |
| **Prompt injection via response body**          | Body returned to the agent contains `<|im_start|>system\n…`.                                      | Default `return_body=false`; bodies wrapped in `<untrusted_remote_content>` markers; control characters and bidi overrides stripped. |

## 3. Design principles

1. **Deny-by-default.** No target is reachable without an explicit
   allow-list entry in the YAML policy. The built-in default
   policy has a loopback + public-diagnostic-host allow-list; for
   production you must replace it with your own.
2. **Defence in depth.** Allow-list + IP filter + SafeDialer +
   rate limit + concurrency cap. Any one layer can be bypassed by
   a bug; together they make exploitation much harder.
3. **Immutable configuration at runtime.** No tool call can
   modify the policy. Reload = SIGHUP-restart, not API.
4. **No agent-controlled bytes on the wire.** `tcp_probe` only
   runs hard-coded named dialogues. `http_probe` may not send a
   body unless `allow_request_body=true`. Body bytes are sanitised
   and bounded.
5. **Bounded budget.** Every probe has a per-tool timeout, a
   global `probes.max_timeout` (default 30s, hard cap 60s), and a
   session quota (default 500 calls). `MaxConcurrentProbes`
   caps goroutines.
6. **Auditability.** Every tool call produces an immutable JSON
   audit record (`audit.Event`). The `outbound_urls` field
   captures every URL the diagnostic emitted a request to — the
   only observable trail of secondary SSRF channels.

## 4. Honest limitations

A probe is only as good as its surface area. The v1 analyzer
explicitly does **not** check:

| Check                                           | Why skipped                                                                                                       |
|-------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| **SSLv3 acceptance**                            | Removed from Go's `crypto/tls`. Surfaced in `checks_always_skipped` (resource `probe://capabilities`).            |
| **RC4 / NULL / EXPORT cipher acceptance**        | Removed from `crypto/tls`. Detectable via the raw-ClientHello phase (opt-in) — see `probe://findings/catalog`.     |
| **DHE parameter weakness** (Logjam)              | `crypto/tls` does not offer DHE suites as a client. Cannot be detected.                                              |
| **Client-initiated renegotiation**              | `crypto/tls` does not support it. Cannot be detected.                                                                |
| **TLS compression** (CRIME)                     | `crypto/tls` does not negotiate compression. Cannot be detected.                                                    |
| **ROCA weak keys** (CVE-2017-15361)              | Requires a prime test library not in v1 dependencies. Listed as `TLS_ROCA_VULNERABLE_KEY` (disabled).               |
| **Debian weak keys** (CVE-2008-0166)            | Requires a fingerprint database not in v1 dependencies. Listed as `TLS_DEBIAN_WEAK_KEY` (disabled).                 |
| **Leaf SPKI vs handshake transient key**         | Requires parsing `ServerKeyExchange.signature` against the leaf SPKI. v1 uses the raw-ClientHello probe but does not verify the match. |

The MCP `findings` catalogue (resource `probe://findings/catalog`)
lists every finding ID the server can emit, with its severity,
category, rationale and remediation. An **absence** of a finding is
NOT evidence of a secure configuration when the corresponding
check is structurally impossible — that is what
`probe://capabilities` documents.

## 5. Operator checklist

Before deploying:

- [ ] Edit `configs/policy.example.yaml` to reflect your
      targets. **Do not ship the built-in default to production.**
- [ ] The allow-list should be as tight as possible: exact
      hostnames over wildcards, explicit port ranges, an explicit
      `tools:` list on every rule. A rule without `tools:` matches
      every tool (intentional — use sparingly).
- [ ] Set `audit.log_targets=true` to capture the full target
      string in the audit log; `false` to keep only the typed
      fields. Internal IPs are always scrubbed, regardless.
- [ ] If you intend to expose the HTTP transport, configure
      `server.http.auth.token_bearer.token_hashes` with at least
      one SHA-256 hex digest (generate with `netprobe-mcp hash
      <token>`). The server refuses to start without it.
- [ ] Decide whether AIA chasing and direct OCSP queries are
      acceptable. They are off by default for a reason: the URL
      comes from the certificate, which is attacker-controlled.
      If you turn them on, add explicit `purposes: [aia_fetch]`
      and `purposes: [ocsp_query]` allow-list entries.
- [ ] Bind metrics on `127.0.0.1` only. The metrics endpoint
      exposes counters that can fingerprint your traffic.
- [ ] Do **not** pass `--i-know-what-im-doing` in production. It
      exists so the operator can opt into
      `probes.http.insecure_skip_verify=true` only on
      development hosts.

## 6. Reading the audit log

Each audit record is one JSON line. The fields:

```jsonc
{
  "ts": "2026-01-01T12:00:00Z",          // RFC3339 UTC
  "event_id": "uuid-v4",                // unique per event
  "session_id": "...",                  // MCP session (stdio: "stdio-local")
  "tool": "http_probe",                  // tool name
  "requested_target": "https://…",       // agent-supplied, scrubbed
  "resolved_addr": "[internal-ip]",      // safe-pinned, scrubbed
  "resolved_port": 443,
  "decision": "allowed",                  // allowed | denied
  "deny_reason": "",                     // public message when denied
  "matched_rule": "allow:exact:api.example.com",
  "outcome": "success",                   // success | probe_failure | policy_denied | internal_error
  "duration_ms": 12.4,
  "outbound_urls": [...],                 // AIA / OCSP URLs, host portion scrubbed
  "findings": ["TLS_CHAIN_MISSING_INTERMEDIATE"]  // finding IDs from tls_diagnose
}
```

**Important**: when `audit.log_targets=true`, `requested_target`
and `resolved_addr` are included; in both cases, addresses from
RFC1918, loopback, link-local, CGNAT, ULA, and IPv6 link-local
ranges are replaced with the sentinel `[internal-ip]`. This
prevents an attacker from using the audit log to map your internal
network.

Denials are written **synchronously** — they cannot be lost if the
process is killed mid-probe. Allowed probes are written
asynchronously through a bounded channel (256 entries); if the
channel is full, the event is dropped and
`probe_mcp_audit_dropped_total` is incremented. A non-zero drop
counter indicates the audit consumer is too slow or the event rate
is too high.

## 7. Resources exposed to the agent

Three MCP resources, served read-only:

- `probe://policy` — the effective security policy (allow-list
  counts, rate limits, enabled probes, TLS diagnostic options).
- `probe://capabilities` — runtime capabilities and
  structurally-unavailable checks (e.g. "SSLv3 cannot be probed
  with crypto/tls").
- `probe://findings/catalog` — every TLS finding ID with its
  severity, category, title, rationale and remediation. Generated
  from the actual rule registry; cannot drift.

The model is encouraged to consult `probe://policy` before its
first probe, and `probe://capabilities` whenever an answer is
"this server cannot tell".

## 8. Where to report a vulnerability

Please open a private issue / security advisory on the upstream
repository. Do not disclose security-sensitive details in public
issues or pull requests.

When reporting, please include:

- The version of `netprobe-mcp` (`netprobe-mcp --version`).
- The minimal YAML policy that reproduces the issue (redact
  sensitive values — replace your real targets with
  `example.com`).
- The exact MCP request that triggers the issue (if applicable).
- The audit log entry produced (redact secrets).
