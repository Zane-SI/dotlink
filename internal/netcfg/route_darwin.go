//go:build darwin

package netcfg

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// routeInterfacePattern pulls the one line `route -n get` prints that matters:
// the interface the kernel would send to. Everything else is decoration.
var routeInterfacePattern = regexp.MustCompile(`(?m)^\s*interface:\s*(\S+)\s*$`)

// RouteInterface answers "which interface would a packet to this prefix leave
// through". Empty means the kernel has no route; callers must not treat that
// as an error, because that is also the answer for a LAN behind another
// router with no static route configured.
func RouteInterface(ctx context.Context, r Runner, pr netip.Prefix) (string, error) {
	// -inet6 is not cosmetic: `route -n get -net fd00::/64` on macOS parses
	// the destination as IPv4 and answers with the IPv4 default route.
	family := "-net"
	if pr.Addr().Is6() {
		family = "-inet6"
	}
	out, err := r.Output(ctx, "route", "-n", "get", family, pr.Masked().String())
	if m := routeInterfacePattern.FindStringSubmatch(out); m != nil {
		return m[1], nil
	}
	if err != nil {
		// "not in table" is route(8) saying there is no route, which is an
		// answer. Anything else means the lookup itself broke and the caller
		// must not mistake it for "this Mac cannot reach the LAN".
		if strings.Contains(out, "not in table") {
			return "", nil
		}
		return "", fmt.Errorf("route lookup %s: %w: %s", pr, err, strings.TrimSpace(out))
	}
	// Success with no interface line: the route exists but the kernel did not
	// name an egress interface. Treat it like "no route" rather than guessing.
	return "", nil
}
