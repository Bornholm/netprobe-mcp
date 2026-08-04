// Package auth provides small primitives shared between the CLI
// (cmd/netprobe-mcp) and the MCP server (internal/mcpserver).
//
// It exists so the `netprobe-mcp hash <token>` subcommand can mint
// SHA-256 hex digests without importing the whole MCP server package,
// and so both call sites use the exact same encoding (PLAN §4.3,
// §9.8).
package auth

import (
	"crypto/sha256"
	"fmt"
)

// HashToken returns the lowercase SHA-256 hex digest of the supplied
// token. The output is 64 characters, suitable for pasting into the
// `server.http.auth.token_bearer.token_hashes` list of a policy file.
//
// Tokens are matched verbatim on the server side (constant-time
// compare across the whole digest set); the encoding is intentionally
// minimal so operators can verify a hash with `printf '%s' "$TOKEN"
// | sha256sum`.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum)
}
