# netprobe-mcp

Auditable network probing exposed as a [Model Context Protocol](https://modelcontextprotocol.io) server. A single Go binary that lets an agent run `tcp_probe`, `http_probe`, `dns_probe`, `tls_diagnose`, and `icmp_probe` against an explicit allow-list.

Every probe clears a guard pipeline — allow-list → IP family filter → rate limit → probe — so a misconfigured policy cannot become an SSRF proxy. `probe_policy` and `probe_check_target` answer "what is permitted?" and "is this target allowed?" without consuming any network budget.

## Use with OpenCode

OpenCode discovers MCP servers from `opencode.json` / `opencode.jsonc`. Add a local block that points at the built binary:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "netprobe": {
      "type": "local",
      "command": ["/absolute/path/to/bin/netprobe-mcp"],
      "enabled": true
    }
  }
}
```

For a one-shot registration, the CLI equivalent is:

```bash
opencode mcp add netprobe-mcp -- netprobe-mcp --allow-hostname=<allowed_domain>
```

The `--` separator hands the rest of the line to OpenCode as the command to spawn. Adjust the path to the binary (`netprobe-mcp` must be on `PATH`, or pass an absolute path) and tune `--allow-*` flags to widen the built-in safe default policy without writing a YAML file.

`type: "local"` spawns the binary per OpenCode session and speaks JSON-RPC over its stdio by default. The first agent turn will list `probe_policy`, `probe_check_target`, `tcp_probe`, `http_probe`, `dns_probe`, `tls_diagnose`, and `icmp_probe` in the tool drawer.

## Build

```bash
git clone https://github.com/bornholm/netprobe-mcp
cd netprobe-mcp
make build          # -> bin/netprobe-mcp
```

Requires Go 1.25.7 (pinned in `go.mod`). No cgo, no system dependencies.

## Run standalone

With no flags, the binary loads a built-in safe default policy (loopback + a few public diagnostic hosts) suitable for local evaluation and demos:

```bash
./bin/netprobe-mcp
```

For anything else, point it at a YAML policy:

```bash
./bin/netprobe-mcp --config=configs/policy.example.yaml
# or extend the default without writing a file:
./bin/netprobe-mcp --allow-cidr=10.0.0.0/8 --allow-hostname=.example.com
```

Policy is loaded once at startup. Hot reload is not supported; restart the process to apply changes.

## Quick test

From inside OpenCode, the recommended workflow is:

```
probe_policy                         # see what's allowed
probe_check_target example.com 443   # dry-run, no network
http_probe https://example.com       # actual probe
```

A `success=false` result means the probe ran and the **target** is at fault — do not retry unchanged. A tool result flagged as an error means the request was **refused by policy** — retrying identically will always fail.
