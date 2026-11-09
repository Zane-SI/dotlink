// Package netshare turns an Agent into a Subnet Router: it forwards traffic
// between the Overlay and a LAN, and source-NATs it so the LAN sees the
// Gateway's own address instead of an unroutable 100.64.x.x.
package netshare

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/Zane-SI/dotlink/internal/subnet"
)

// Config is what the Gateway is asked to forward for.
// DefaultTokenPath is where the pf reference token is recorded so a crash can
// release it on the next start. pf keeps a reference count: a token that is
// never released makes pf impossible to turn off. /var/run is root-owned, so a
// non-root user cannot pre-create the file.
const DefaultTokenPath = "/var/run/dotlink-pf.token"

type Config struct {
	// TUN is the interface name, used to spot a route that already points
	// back into the tunnel (forwarding it would loop).
	TUN string
	// Routes are the LANs this Gateway advertises. Empty means nothing to do.
	Routes []netip.Prefix
	// Sources are the Overlay ranges traffic arrives from. Defaults to the
	// v1 pools when nil.
	Sources []netip.Prefix
	// RuleDir is where the pf anchor file is written. Empty means the
	// system temp directory; tests point it at t.TempDir().
	RuleDir string
	// TokenPath records the pfctl -E reference token. Empty disables crash
	// recovery; tests point it at t.TempDir().
	TokenPath string
}

// DefaultSources is the v1 Overlay address space (spec §5).
func DefaultSources() []netip.Prefix {
	return []netip.Prefix{subnet.OverlayV4, subnet.OverlayV6}
}

// pfRules is the whole NAT policy as text. Pure so it can be read in a test
// without root: a wrong rule here silently leaks private addresses onto a LAN.
func pfRules(ifaces []string, v4, v6 []netip.Prefix) string {
	var b strings.Builder
	b.WriteString("# dotlink Subnet Router: traffic from the Overlay leaves as the\n")
	b.WriteString("# Gateway's LAN address, so replies come back to a routable host.\n")
	for _, iface := range ifaces {
		for _, src := range v4 {
			fmt.Fprintf(&b, "nat on %s inet from %s to any -> (%s)\n", iface, src, iface)
			fmt.Fprintf(&b, "pass out quick on %s inet from %s to any keep state\n", iface, src)
		}
		for _, src := range v6 {
			fmt.Fprintf(&b, "nat on %s inet6 from %s to any -> (%s)\n", iface, src, iface)
			fmt.Fprintf(&b, "pass out quick on %s inet6 from %s to any keep state\n", iface, src)
		}
	}
	return b.String()
}

// splitByFamily keeps the rule text honest: a v6 NAT rule written with an
// inet4 address is a pf parse error, not a warning.
func splitByFamily(ps []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range ps {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

// uniq keeps interface order stable while dropping repeats: two LANs behind
// one NIC should produce one rule set, not duplicates pf would reject.
func uniq(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
