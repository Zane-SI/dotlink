//go:build linux

package netcfg

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// RouteInterface asks iproute2 which device a packet to pr would leave
// through. Empty means the kernel has no route (which is an answer, not an
// error): the LAN may be reachable only through a router that is not
// configured on this host.
func RouteInterface(ctx context.Context, r Runner, pr netip.Prefix) (string, error) {
	args := []string{"route", "get", pr.Masked().String()}
	if pr.Addr().Is6() {
		args = append([]string{"-6"}, args...)
	}
	out, err := r.Output(ctx, "ip", args...)
	if err != nil {
		low := strings.ToLower(out + " " + err.Error())
		if strings.Contains(low, "no route") || strings.Contains(low, "network is unreachable") || strings.Contains(low, "invalid argument") {
			return "", nil
		}
		return "", fmt.Errorf("ip route get %s: %w: %s", pr, err, strings.TrimSpace(out))
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("ip route get %s: no dev in %q", pr, strings.TrimSpace(out))
}
