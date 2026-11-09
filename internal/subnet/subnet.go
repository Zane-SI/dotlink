// Package subnet owns the rules for a Subnet Router advertisement. Both the
// Agent (before it touches a privileged interface) and the Control Plane
// (before it stores a claim) use it, so a route that one accepts cannot be
// rejected by the other for a different reason.
package subnet

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// MaxRoutes bounds one Gateway's advertisement. A home network has one or two
// LANs; anything past this is a loop that forgot its base case.
const MaxRoutes = 16

// The two Overlay ranges, as prefixes: a subnet route may not overlap either,
// because the tunnel would then compete with itself.
var (
	OverlayV4 = netip.MustParsePrefix("100.64.0.0/10")
	OverlayV6 = netip.MustParsePrefix("fd00::/64")
)

// Parse canonicalizes and sanity-checks a wire advertisement. The order of
// checks is part of the error contract: tests and users rely on "too broad"
// winning over "unspecified", and on the limit being reported before any
// individual prefix is parsed.
func Parse(in []string) ([]string, error) {
	if len(in) > MaxRoutes {
		return nil, fmt.Errorf("at most %d subnet routes", MaxRoutes)
	}
	parsed := make([]netip.Prefix, 0, len(in))
	for _, raw := range in {
		pr, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR prefix", raw)
		}
		parsed = append(parsed, pr)
	}
	normalized, err := Normalize(parsed)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(normalized))
	for _, pr := range normalized {
		out = append(out, pr.String())
	}
	return out, nil
}

// Normalize masks, validates, dedupes and sorts an advertisement. Masking is
// not cosmetic: 192.168.1.9/24 and 192.168.1.0/24 are the same LAN, and
// installing both would run the same route twice and fail the second time.
func Normalize(in []netip.Prefix) ([]netip.Prefix, error) {
	if len(in) > MaxRoutes {
		return nil, fmt.Errorf("at most %d subnet routes", MaxRoutes)
	}
	out := make([]netip.Prefix, 0, len(in))
	seen := make(map[netip.Prefix]bool, len(in))
	for _, pr := range in {
		if !pr.IsValid() {
			return nil, fmt.Errorf("%q is not a CIDR prefix", pr)
		}
		pr = pr.Masked()
		if err := check(pr); err != nil {
			return nil, err
		}
		if seen[pr] {
			continue
		}
		seen[pr] = true
		out = append(out, pr)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out, nil
}

func check(pr netip.Prefix) error {
	if pr.Addr().Is4In6() {
		return fmt.Errorf("%s is an IPv4-mapped IPv6 prefix; advertise the IPv4 form", pr)
	}
	if pr.Bits() == 0 {
		return fmt.Errorf("%s is a default route; exit nodes are not in v1", pr)
	}
	// A Subnet Router forwards a LAN, not a whole address family: a /1 would
	// silently take over half the internet for every peer.
	if pr.Addr().Is4() && pr.Bits() < 8 {
		return fmt.Errorf("%s is too broad for a subnet route; the IPv4 minimum is /8", pr)
	}
	if pr.Addr().Is6() && pr.Bits() < 16 {
		return fmt.Errorf("%s is too broad for a subnet route; the IPv6 minimum is /16", pr)
	}
	if pr.Addr().Is4() && OverlayV4.Overlaps(pr) {
		return fmt.Errorf("%s overlaps the Overlay range %s", pr, OverlayV4)
	}
	if pr.Addr().Is6() && OverlayV6.Overlaps(pr) {
		return fmt.Errorf("%s overlaps the Overlay range %s", pr, OverlayV6)
	}
	switch {
	case pr.Addr().IsUnspecified():
		return fmt.Errorf("%s is unspecified; a peer could never route to it", pr)
	case pr.Addr().IsLoopback():
		return fmt.Errorf("%s is loopback; a peer could never route to it", pr)
	case pr.Addr().IsLinkLocalUnicast():
		return fmt.Errorf("%s is link-local; a peer could never route to it", pr)
	case pr.Addr().IsLinkLocalMulticast() || pr.Addr().IsMulticast():
		return fmt.Errorf("%s is multicast; a peer could never route to it", pr)
	}
	return nil
}
