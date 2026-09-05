# AGENTS.md — netprobe-mcp

## What this is

A Go MCP server (`github.com/bornholm/netprobe-mcp`) that exposes auditable network probing (`tcp_probe`, `http_probe`, `dns_probe`, `tls_diagnose`, `icmp_probe`, `probe_check_target`, `probe_policy`) over stdio or streamable HTTP. Every probe must clear a guard pipeline: allow-list → IP filter → rate limit → probe. Single binary, no cgo.

## Layout

- `cmd/netprobe-mcp` — entrypoint, flags, dependency wiring. Bin: `bin/netprobe-mcp`.
- `internal/build` — ldflags-injected `Version` / `LongVersion` (default `"dev"`).
- `internal/config` — YAML policy loader + `Config.Validate()`. Empty `--config` loads a built-in safe default (loopback + a few public diagnostic hosts). Hot reload is not supported.
- `internal/security` — Guard pipeline. `Guard.Authorize` returns the only `SafeTarget` value downstream may dial. `NormalizeHost` rejects non-canonical IP encodings and unqualified hostnames. `NormalizeQueryName` is its counterpart for a DNS QNAME, which is not a host name: it admits the underscored labels of RFC 8552 (`_dmarc`, `_domainkey`, `_tcp`) and is reached only through `Guard.CheckQueryName`. `errs.DenyError` is the typed error shared across `security`, `ratelimit`, `mcpserver`.
- `internal/ratelimit` — global/per-tool/per-target/per-session token buckets, keyed TTL janitor, concurrency cap.
- `internal/probe` — TCP, HTTP, DNS probers + sanitization.
- `internal/probe/icmp` — ICMP prober. Boots with `DetectCapability()` once; tries unprivileged UDP first, then raw socket, then `ModeUnavailable`. 200ms floor on `interval_ms`.
- `internal/probe/tlsdiag` — TLS analyzer. Passive by default; `aia_fetch` and `ocsp_direct` need both `cfg.AllowAIAFetch`/`AllowOCSPQuery` and the per-call flag, otherwise they appear in `checks_skipped`.
- `internal/mcpserver` — wires tools, resources, MCP middleware (audit + recovery). `newTestServer` builds a fixture with loopback-only allow-list.
- `internal/audit`, `internal/metrics` — JSON audit (stderr default, methods, no targets by default) and `/metrics` (loopback `127.0.0.1:9101` default).

## Build / verify (run from repo root)

```bash
make build         # go build -o bin/netprobe-mcp ./cmd/netprobe-mcp
make test          # go test -count=1 ./...
make test-race     # go test -race -count=1 ./...
make fuzz          # 10s fuzz of each name normalizer (host, query name)
make lint          # go vet ./...
make run           # ./bin/netprobe-mcp --config=configs/policy.example.yaml
```

CI runs the same plus `gofmt -l .` (fails on unformatted files) and a fuzz job giving 30s to each of `FuzzNormalizeHost` and `FuzzNormalizeQueryName` (`-fuzz` takes one target at a time). Release is `goreleaser` on `v*` tags; PRs run it in `--snapshot` mode.

## Single-package / focused tests

```bash
go test -run TestIntegration_AllowedTargetConnects ./internal/mcpserver/...
go test -count=1 -race ./internal/security/...     # guard + matcher + sanitize
go test -run '^$' -fuzz=^FuzzNormalizeHost$ -fuzztime=30s ./internal/security/
go test -run '^$' -fuzz=^FuzzNormalizeQueryName$ -fuzztime=30s ./internal/security/
```

Goroutine leak detectors (use `goleak.VerifyTestMain`) live in:

- `internal/probe/icmp/main_test.go` — ignores `internal/poll.runtime_pollWait`; uses `t.Context()` so the raw-socket multiplexer reader exits.
- `internal/mcpserver/main_test.go` — ignores `net.(*TCPListener).Accept` and `audit.(*Logger).run`; `quietListener` helper keeps Accept busy without leaks.

## Conventions / gotchas

- **Deny by default.** `config.Validate()` rejects empty `security.targets.allow`; HTTP transport refuses to start without `auth.token_bearer.token_hashes` (64-char hex SHA-256). Tokens are stored as hex digests, never plaintext. Generate via `netprobe-mcp hash <token>`.
- **Tool allow-list per rule.** A rule without `tools:` matches nothing. CI / fixture configs list every tool explicitly.
- **A `cidr` rule can never allow a QNAME.** `Guard.CheckQueryName` validates the queried name *without resolving it*, so only the textual rules — `exact`, `suffix`, `glob`, `regexp` — are evaluated. A policy whose allow-list is CIDR-only lets every address-based probe through and refuses every DNS question, which reads like a broken domain rather than a broken policy. `glob` is a poor fit here too: the pattern must contain a dot and `**` does not cross an arbitrary number of labels.
- **`probes.dns.allowed_query_types` defaults to `["A", "AAAA"]`** whenever a policy file is supplied. MX, TXT, NS, SOA and CAA — the records a mail or delegation diagnostic is actually about — have to be listed. `AXFR` and `ANY` are refused by `isKnownQType` regardless.
- **`probes.*` defaults are not `config.Default()`.** `config.Load` applies `Validate()` to a supplied file, and `Validate` fills gaps under `security.dns` but not under `probes.dns`. `block_high_entropy_labels` in particular is `true` in `Default()` and `false` in any hand-written policy that omits it — the anti-tunnelling heuristic silently off.
- **ICMP privilege.** Preferred path is unprivileged UDP (`net.ipv4.ping_group_range`). Raw socket needs `CAP_NET_RAW`. Never setuid root. `payload_size` capped at 1400, `count` clamped to 10, `interval_ms` floor 200.
- **TLS secondary channels.** `aia_fetch` / `ocsp_direct` mutate `checks_skipped` and surface as `disabled by config` when the operator hasn't enabled them — even if the per-call flag is set.
- **Build-time vars.** `internal/build.Version` and `LongVersion` are overwritten by goreleaser ldflags; tests assert `"dev"`/`"dev (unknown)"` defaults. Don't introduce init-order hacks that read them before `main()`.
