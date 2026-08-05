package security

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/bornholm/netprobe-mcp/internal/config"
)

type MatchKind int

const (
	MatchExact MatchKind = iota
	MatchSuffix
	MatchGlob
	MatchRegexp
	MatchCIDR
)

type compiledRule struct {
	id      string
	kind    MatchKind
	raw     string
	exact   string
	suffix  string
	glob    string
	re      *regexp.Regexp
	cidr    netip.Prefix
	ports   []portRange
	schemes map[string]struct{}
	tools   map[string]struct{}
	// purposes restricts the rule to a closed set of purpose
	// strings. Empty means "any purpose".
	purposes map[string]struct{}
	// methods restricts the rule to a closed set of HTTP methods
	// (uppercase). Empty means "any method".
	methods map[string]struct{}
	// paths restricts the rule to a closed set of HTTP path
	// globs (already compiled). Empty means "any path".
	paths   []pathMatcher
	comment string
}

type portRange struct {
	from, to uint16
}

func (r *compiledRule) portAllowed(p uint16) bool {
	if len(r.ports) == 0 {
		return true
	}
	for _, pr := range r.ports {
		if p >= pr.from && p <= pr.to {
			return true
		}
	}
	return false
}

func (r *compiledRule) schemeAllowed(s string) bool {
	if len(r.schemes) == 0 {
		return true
	}
	_, ok := r.schemes[strings.ToLower(s)]
	return ok
}

func (r *compiledRule) toolAllowed(t string) bool {
	if len(r.tools) == 0 {
		return true
	}
	_, ok := r.tools[t]
	return ok
}

// methodAllowed reports whether the given HTTP method (already
// normalized to upper-case by the caller) is permitted by the rule.
// An empty rule set means "any method"; the HTTP probe's own
// hard-coded allow-list still applies on top.
func (r *compiledRule) methodAllowed(m string) bool {
	if len(r.methods) == 0 {
		return true
	}
	_, ok := r.methods[m]
	return ok
}

// pathsAllowed reports whether the given HTTP path is permitted by
// the rule. An empty rule set means "any path". Path globs are
// matched with the same syntax as the rule's host globs: '*' matches
// any run of characters within a label, '**' crosses dots.
func (r *compiledRule) pathsAllowed(p string) bool {
	if len(r.paths) == 0 {
		return true
	}
	for _, pm := range r.paths {
		if pm.Match(p) {
			return true
		}
	}
	return false
}

func (r *compiledRule) purposeAllowed(p Purpose) bool {
	if len(r.purposes) == 0 {
		return true
	}
	_, ok := r.purposes[string(p)]
	return ok
}

func (r *compiledRule) matchesHost(host string) bool {
	switch r.kind {
	case MatchExact:
		return host == r.exact
	case MatchSuffix:
		return host == r.suffix || strings.HasSuffix(host, "."+r.suffix)
	case MatchGlob:
		return globMatch(r.glob, host)
	case MatchRegexp:
		return r.re.MatchString(host)
	case MatchCIDR:
		return false // CIDR matches on IP, not on hostname; handled separately
	}
	return false
}

// globMatch supports '*' (matches any run of characters in a label) and
// '**' (crosses dots). The matching is conservative: partial label matches
// are not allowed.
func globMatch(pattern, host string) bool {
	// Translate to anchored regexp.
	parts := strings.Split(pattern, "**")
	if len(parts) > 2 {
		return false
	}
	if len(parts) == 1 {
		return matchGlobSegment(parts[0], host, false)
	}
	pre, post := parts[0], parts[1]
	if !strings.HasPrefix(host, strings.TrimRight(pre, "*")) && pre != "" {
		return false
	}
	if post != "" && !strings.HasSuffix(host, strings.TrimLeft(post, "*")) {
		return false
	}
	return true
}

func matchGlobSegment(seg, host string, anchored bool) bool {
	if seg == "" {
		return true
	}
	// Convert to regexp
	var b strings.Builder
	b.WriteString("^")
	star := false
	for _, r := range seg {
		switch r {
		case '*':
			star = true
		default:
			if star {
				b.WriteString("[^.]*")
				star = false
			}
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	if star {
		b.WriteString("[^.]*")
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(host)
}

// pathMatcher is the compiled form of a single HTTP path glob from a
// TargetRule. It re-uses the same syntax as the host glob matcher:
// '*' matches a run of characters inside a segment (separator is '/'
// for paths), '**' crosses segments. Path matching is
// case-sensitive (HTTP paths are case-sensitive by spec, unlike DNS
// labels).
type pathMatcher struct {
	raw    string
	prefix string // segment preceding the first '**'
	suffix string // segment following the last '**'
	only   string // entire pattern when there is no '**'
}

func compilePathPattern(p string) (pathMatcher, error) {
	if p == "" {
		return pathMatcher{}, errInvalid("path glob is empty")
	}
	if !strings.HasPrefix(p, "/") {
		return pathMatcher{}, errInvalid("path glob must start with '/'")
	}
	parts := strings.Split(p, "**")
	if len(parts) > 2 {
		return pathMatcher{}, errInvalid("path glob may contain at most one '**'")
	}
	if len(parts) == 1 {
		return pathMatcher{raw: p, only: p}, nil
	}
	return pathMatcher{
		raw:    p,
		prefix: parts[0],
		suffix: parts[1],
	}, nil
}

func (pm pathMatcher) Match(p string) bool {
	if pm.only != "" {
		return matchPathSegment(pm.only, p, false)
	}
	if pm.prefix != "" && !strings.HasPrefix(p, strings.TrimRight(pm.prefix, "*")) {
		return false
	}
	if pm.suffix != "" && !strings.HasSuffix(p, strings.TrimLeft(pm.suffix, "*")) {
		return false
	}
	return true
}

// matchPathSegment is the path-flavored counterpart of
// matchGlobSegment: '*' matches any run of characters within a single
// segment (separator is '/'), so '/v1/*' matches '/v1/status' but
// not '/v1/users/42'.
func matchPathSegment(seg, path string, anchored bool) bool {
	if seg == "" {
		return true
	}
	var b strings.Builder
	b.WriteString("^")
	star := false
	for _, r := range seg {
		switch r {
		case '*':
			star = true
		default:
			if star {
				b.WriteString("[^/]*")
				star = false
			}
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	if star {
		b.WriteString("[^/]*")
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(path)
}

func compileRule(idx int, isAllow bool, rule config.TargetRule) (*compiledRule, error) {
	r := &compiledRule{
		id:      makeRuleID(isAllow, idx, rule.Type, rule.Pattern),
		raw:     rule.Pattern,
		comment: rule.Comment,
	}
	switch rule.Type {
	case "exact":
		host, err := NormalizeHost(rule.Pattern)
		if err != nil {
			return nil, err
		}
		r.kind = MatchExact
		r.exact = host
	case "suffix":
		if !strings.Contains(rule.Pattern, ".") {
			return nil, errInvalid("suffix pattern must contain a dot")
		}
		host, err := NormalizeHost(rule.Pattern)
		if err != nil {
			return nil, err
		}
		r.kind = MatchSuffix
		r.suffix = host
	case "glob":
		if !strings.Contains(rule.Pattern, ".") {
			return nil, errInvalid("glob pattern must contain a dot")
		}
		r.kind = MatchGlob
		r.glob = strings.ToLower(rule.Pattern)
	case "regexp":
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, err
		}
		r.kind = MatchRegexp
		r.re = re
	case "cidr":
		p, err := netip.ParsePrefix(rule.Pattern)
		if err != nil {
			return nil, err
		}
		r.kind = MatchCIDR
		r.cidr = p
	default:
		return nil, errInvalid("unknown rule type " + rule.Type)
	}
	if len(rule.Ports) > 0 {
		for _, p := range rule.Ports {
			if p.From > p.To {
				return nil, errInvalid("port range invalid")
			}
			r.ports = append(r.ports, portRange{from: p.From, to: p.To})
		}
	}
	if len(rule.Schemes) > 0 {
		r.schemes = make(map[string]struct{}, len(rule.Schemes))
		for _, s := range rule.Schemes {
			r.schemes[strings.ToLower(s)] = struct{}{}
		}
	}
	if len(rule.Tools) > 0 {
		r.tools = make(map[string]struct{}, len(rule.Tools))
		for _, t := range rule.Tools {
			r.tools[t] = struct{}{}
		}
	}
	if len(rule.Methods) > 0 {
		r.methods = make(map[string]struct{}, len(rule.Methods))
		for _, m := range rule.Methods {
			up := strings.ToUpper(strings.TrimSpace(m))
			if up == "" {
				return nil, errInvalid("methods contains an empty entry")
			}
			r.methods[up] = struct{}{}
		}
	}
	if len(rule.Paths) > 0 {
		r.paths = make([]pathMatcher, 0, len(rule.Paths))
		for _, p := range rule.Paths {
			pm, err := compilePathPattern(p)
			if err != nil {
				return nil, err
			}
			r.paths = append(r.paths, pm)
		}
	}
	if len(rule.Purposes) > 0 {
		r.purposes = make(map[string]struct{}, len(rule.Purposes))
		for _, p := range rule.Purposes {
			r.purposes[p] = struct{}{}
		}
	}
	return r, nil
}

func makeRuleID(isAllow bool, idx int, kind, pattern string) string {
	prefix := "deny"
	if isAllow {
		prefix = "allow"
	}
	return prefix + ":" + kind + ":" + truncate(pattern, 32)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

type errInvalidStr string

func (e errInvalidStr) Error() string { return string(e) }

func errInvalid(msg string) error { return errInvalidStr(msg) }

type MatchResult struct {
	Allowed    bool
	Rule       *compiledRule
	DenyReason string
}

type TargetMatcher struct {
	allow      []*compiledRule
	deny       []*compiledRule
	allowExact map[string][]*compiledRule
	denyExact  map[string]struct{}
}

func NewTargetMatcher(allowRules, denyRules []config.TargetRule) (*TargetMatcher, error) {
	m := &TargetMatcher{
		allowExact: make(map[string][]*compiledRule),
		denyExact:  make(map[string]struct{}),
	}
	for i, r := range allowRules {
		c, err := compileRule(i, true, r)
		if err != nil {
			return nil, err
		}
		m.allow = append(m.allow, c)
		if c.kind == MatchExact {
			m.allowExact[c.exact] = append(m.allowExact[c.exact], c)
		}
	}
	for i, r := range denyRules {
		c, err := compileRule(i, false, r)
		if err != nil {
			return nil, err
		}
		m.deny = append(m.deny, c)
		if c.kind == MatchExact {
			m.denyExact[c.exact] = struct{}{}
		}
	}
	return m, nil
}

// Match returns the first allow rule that matches the request (deny wins).
// IP is optional: when non-zero, cidr rules are evaluated against it too.
// method is upper-cased by the caller; path is taken verbatim from
// the URL (case-sensitive).
//
// Only the **essential** constraints (host/CIDR, tool, purpose) are
// evaluated here. The remaining constraints (port, scheme, method,
// path) are surfaced on the returned Rule and checked one by one
// in Guard.Authorize so the refusal carries a precise category
// (DenyPort, DenyScheme, DenyMethod, DenyPath) instead of the
// generic "host not in allow-list".
func (m *TargetMatcher) Match(host string, scheme string, port uint16, ip netip.Addr, tool string, purpose Purpose, method string, path string) MatchResult {
	host = strings.ToLower(host)
	method = strings.ToUpper(method)

	if _, ok := m.denyExact[host]; ok {
		return MatchResult{Allowed: false, DenyReason: "host explicitly denied"}
	}
	for _, r := range m.deny {
		if r.kind == MatchCIDR {
			if ip.IsValid() && r.cidr.Contains(ip) {
				return MatchResult{Allowed: false, DenyReason: "CIDR explicitly denied"}
			}
			continue
		}
		if r.matchesHost(host) {
			return MatchResult{Allowed: false, DenyReason: "host explicitly denied"}
		}
	}

	for _, r := range m.allowExact[host] {
		if r.toolAllowed(tool) && r.purposeAllowed(purpose) {
			return MatchResult{Allowed: true, Rule: r}
		}
	}
	for _, r := range m.allow {
		if r.kind == MatchExact {
			continue
		}
		if r.kind == MatchCIDR {
			if !ip.IsValid() || !r.cidr.Contains(ip) {
				continue
			}
		} else if !r.matchesHost(host) {
			continue
		}
		if r.toolAllowed(tool) && r.purposeAllowed(purpose) {
			return MatchResult{Allowed: true, Rule: r}
		}
	}
	return MatchResult{Allowed: false, DenyReason: "host not in allow-list"}
}
