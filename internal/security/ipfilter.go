package security

import (
	"net/netip"

	"github.com/bornholm/netprobe-mcp/internal/config"
)

// defaultBogons is always applied unless explicitly overridden by a config
// block that disables the corresponding boolean toggle.
var defaultBogons = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.31.196.0/24",
	"192.52.193.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::/128",
	"::1/128",
	"::ffff:0:0/96",
	"64:ff9b::/96",
	"100::/64",
	"2001::/32",
	"2001:20::/28",
	"2001:db8::/32",
	"2002::/16",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
	"fd00:ec2::254/128",
}

type IPFilter struct {
	cfg     *config.NetworkPolicy
	deny    []netip.Prefix
	allow   []netip.Prefix
	allowV4 bool
	allowV6 bool
}

func NewIPFilter(cfg *config.NetworkPolicy) (*IPFilter, error) {
	f := &IPFilter{
		cfg:     cfg,
		allowV4: cfg.IPv4Allowed(),
		allowV6: cfg.IPv6Allowed(),
	}
	if !cfg.DisableDefaultBogons {
		for _, s := range defaultBogons {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, err
			}
			f.deny = append(f.deny, p)
		}
	}
	for _, s := range cfg.DenyCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		f.deny = append(f.deny, p)
	}
	for _, s := range cfg.AllowCIDRs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		f.allow = append(f.allow, p)
	}
	return f, nil
}

// Check refuses an IP that is invalid, wrong family, semantically restricted
// or falls within an explicit deny-prefix. If allowCIDRs is non-empty, the
// IP must also fall within an allow prefix.
func (f *IPFilter) Check(addr netip.Addr) error {
	if !addr.IsValid() {
		return &DenyError{Category: DenyMalformed, Reason: "invalid IP address"}
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() && !f.allowV4 {
		return &DenyError{Category: DenyIPFamily, Reason: "IPv4 disabled by policy"}
	}
	if addr.Is6() && !f.allowV6 {
		return &DenyError{Category: DenyIPFamily, Reason: "IPv6 disabled by policy"}
	}
	switch {
	case addr.IsLoopback() && f.cfg.LoopbackBlocked():
		return &DenyError{Category: DenyIPRange, Reason: "loopback address not permitted"}
	case addr.IsPrivate() && f.cfg.PrivateBlocked():
		return &DenyError{Category: DenyIPRange, Reason: "private address not permitted"}
	case addr.IsLinkLocalUnicast() && f.cfg.LinkLocalBlocked():
		return &DenyError{Category: DenyIPRange, Reason: "link-local address not permitted"}
	case addr.IsLinkLocalMulticast():
		return &DenyError{Category: DenyIPRange, Reason: "link-local multicast not permitted"}
	case addr.IsMulticast() && f.cfg.MulticastBlocked():
		return &DenyError{Category: DenyIPRange, Reason: "multicast not permitted"}
	case addr.IsUnspecified() && f.cfg.UnspecifiedBlocked():
		return &DenyError{Category: DenyIPRange, Reason: "unspecified address not permitted"}
	case addr.IsInterfaceLocalMulticast():
		return &DenyError{Category: DenyIPRange, Reason: "interface-local multicast not permitted"}
	}
	for _, p := range f.deny {
		if p.Contains(addr) {
			return &DenyError{Category: DenyIPRange, Reason: "address in denied range"}
		}
	}
	if len(f.allow) > 0 {
		for _, p := range f.allow {
			if p.Contains(addr) {
				return nil
			}
		}
		return &DenyError{Category: DenyIPRange, Reason: "address not in allowed ranges"}
	}
	return nil
}
