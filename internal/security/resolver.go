package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bornholm/netprobe-mcp/internal/config"
)

// ResolveResult is what SafeResolver hands back: filtered, validated addresses
// that downstream code is allowed to use without any further network lookup.
type ResolveResult struct {
	Hostname string
	Addrs    []netip.Addr
	// FromCache is true if the entry came from the local cache (no DNS query).
	FromCache bool
	// Duration is the wall-clock time of the lookup (0 when FromCache).
	Duration time.Duration
	// Resolver is the address of the resolver that succeeded (for audit).
	Resolver string
}

type RejectedAddr struct {
	Addr   netip.Addr
	Reason string
}

// LookupFunc abstracts the actual DNS query so tests can swap in a fake.
// The third argument is the hostname to resolve; the resolver address is
// captured by the constructor that produced this LookupFunc.
type LookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func systemLookup(network, server string) (resolverName string, fn LookupFunc) {
	r := &net.Resolver{PreferGo: true}
	if server == "" {
		resolverName = "system"
	} else {
		resolverName = server
	}
	return resolverName, func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		ips, err := r.LookupIP(ctx, network, host)
		if err != nil {
			return nil, err
		}
		out := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			a, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			a = a.Unmap()
			out = append(out, a)
		}
		return out, nil
	}
}

type SafeResolver struct {
	cfg     config.DNSPolicy
	filter  *IPFilter
	mu      sync.RWMutex
	cache   *dnsCache
	reports []ResolveReport
}

// ResolveReport is appended to a bounded ring for the audit log; it captures
// hostname, decisions and durations.
type ResolveReport struct {
	Hostname  string
	Rejected  []RejectedAddr
	FromCache bool
	Duration  time.Duration
	At        time.Time
}

func NewSafeResolver(cfg config.DNSPolicy, filter *IPFilter) *SafeResolver {
	return &SafeResolver{
		cfg:    cfg,
		filter: filter,
		cache:  newDNSCache(cfg.CacheMaxEntries, cfg.CacheTTL),
	}
}

// LookupIPAddr resolves a hostname or IP literal. The result is always
// filtered against the IP filter; the returned list never contains
// disallowed addresses. When the input is already an IP literal, no DNS
// query is performed.
func (r *SafeResolver) LookupIPAddr(ctx context.Context, host string) (*ResolveResult, error) {
	host, err := NormalizeHost(host)
	if err != nil {
		return nil, err
	}

	// IP literal path: no DNS, just filter.
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		if err := r.filter.Check(addr); err != nil {
			return nil, err
		}
		return &ResolveResult{Hostname: host, Addrs: []netip.Addr{addr}}, nil
	}

	if err := ValidateIPLiteral(host); err == nil {
		// It looks numeric but is not a valid IPv4/IPv6 — refuse.
		return nil, &DenyError{Category: DenyMalformed, Reason: "unparseable host (likely non-canonical IP encoding)"}
	}

	// Cache lookup (filtered, safe to return as-is).
	if cached := r.cache.Get(host); cached != nil {
		cp := *cached
		cp.FromCache = true
		return &cp, nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()

	start := time.Now()
	addrs, resolverName, err := r.lookupWithFallback(ctx, host)
	dur := time.Since(start)
	if err != nil {
		de := &DenyError{
			Category: DenyDNSFailure,
			Reason:   "DNS resolution failed",
			Internal: err,
		}
		return nil, de.WithHint("check the hostname and that a resolver is reachable")
	}

	out := &ResolveResult{Hostname: host, Duration: dur, Resolver: resolverName}
	max := r.cfg.MaxAddressesPerName
	for _, a := range addrs {
		if a.Is4In6() {
			a = a.Unmap()
		}
		if ferr := r.filter.Check(a); ferr != nil {
			continue
		}
		// Sort for determinism so that the cached pinned IP is stable.
		out.Addrs = append(out.Addrs, a)
		if len(out.Addrs) >= max {
			break
		}
	}
	sort.Slice(out.Addrs, func(i, j int) bool { return out.Addrs[i].Less(out.Addrs[j]) })

	if len(out.Addrs) == 0 {
		return nil, &DenyError{
			Category: DenyIPRange,
			Reason:   "host resolves to no permitted address",
			Hint:     "all resolved addresses were rejected by the IP filter (possible DNS rebinding)",
		}
	}

	r.cache.Put(host, out)
	return out, nil
}

func (r *SafeResolver) lookupWithFallback(ctx context.Context, host string) ([]netip.Addr, string, error) {
	servers := r.cfg.Resolvers
	if len(servers) == 0 {
		name, fn := systemLookup("ip", "")
		addrs, err := fn(ctx, "ip", host)
		return addrs, name, err
	}
	var lastErr error
	for _, srv := range servers {
		name, fn := systemLookup("ip", srv)
		addrs, err := fn(ctx, "ip", host)
		if err == nil && len(addrs) > 0 {
			return addrs, name, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no addresses returned")
	}
	return nil, "", fmt.Errorf("all resolvers failed: %w", lastErr)
}

// LRU cache of resolved hostnames with a TTL. Entries are filtered
// resolutions, safe to serve directly without re-checking the IP filter.
type dnsCache struct {
	mu       sync.RWMutex
	maxSize  int
	ttl      time.Duration
	entries  map[string]*cacheEntry
	lru      *lruList
	resolved map[string]struct{}
}

type cacheEntry struct {
	res       *ResolveResult
	expiresAt time.Time
	elem      *lruElem
}

func newDNSCache(maxSize int, ttl time.Duration) *dnsCache {
	return &dnsCache{
		maxSize:  maxSize,
		ttl:      ttl,
		entries:  make(map[string]*cacheEntry),
		lru:      newLRU(),
		resolved: make(map[string]struct{}),
	}
}

func (c *dnsCache) Get(host string) *ResolveResult {
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Now().After(e.expiresAt) {
		c.mu.Lock()
		delete(c.entries, host)
		c.lru.remove(e.elem)
		c.mu.Unlock()
		return nil
	}
	c.mu.Lock()
	c.lru.moveToFront(e.elem)
	c.mu.Unlock()
	cp := *e.res
	cp.Addrs = append([]netip.Addr(nil), e.res.Addrs...)
	return &cp
}

func (c *dnsCache) Put(host string, res *ResolveResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[host]; ok {
		e.res = res
		e.expiresAt = time.Now().Add(c.ttl)
		c.lru.moveToFront(e.elem)
		return
	}
	for len(c.entries) >= c.maxSize {
		oldest := c.lru.back()
		if oldest == nil {
			break
		}
		delete(c.entries, oldest.host)
		c.lru.remove(oldest)
	}
	e := &cacheEntry{
		res:       res,
		expiresAt: time.Now().Add(c.ttl),
	}
	e.elem = c.lru.pushFront(host, e)
	c.entries[host] = e
}

// Lightweight LRU avoiding container/list generics complexity.
type lruElem struct {
	host  string
	prev  *lruElem
	next  *lruElem
	entry *cacheEntry
}

type lruList struct {
	head *lruElem
	tail *lruElem
}

func newLRU() *lruList { return &lruList{} }

func (l *lruList) pushFront(host string, entry *cacheEntry) *lruElem {
	e := &lruElem{host: host, entry: entry}
	if l.head == nil {
		l.head = e
		l.tail = e
	} else {
		e.next = l.head
		l.head.prev = e
		l.head = e
	}
	return e
}

func (l *lruList) remove(e *lruElem) {
	if e.prev != nil {
		e.prev.next = e.next
	} else if l.head == e {
		l.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if l.tail == e {
		l.tail = e.prev
	}
	e.prev = nil
	e.next = nil
}

func (l *lruList) moveToFront(e *lruElem) {
	if l.head == e {
		return
	}
	l.remove(e)
	e.prev = nil
	e.next = l.head
	if l.head != nil {
		l.head.prev = e
	}
	l.head = e
	if l.tail == nil {
		l.tail = e
	}
}

func (l *lruList) back() *lruElem { return l.tail }

// helper for tests
func (l *lruList) len() int {
	n := 0
	for e := l.head; e != nil; e = e.next {
		n++
	}
	return n
}

// stringsLastIndex returns the last index of substr in s, or -1.
func stringsLastIndex(s, substr string) int {
	for i := len(s) - len(substr); i >= 0; i-- {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// silence "imported and not used" if test helpers above stay unused.
var _ = strings.LastIndex
var _ = stringsLastIndex
