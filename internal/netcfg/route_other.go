//go:build !darwin && !linux

package netcfg

import (
	"context"
	"net/netip"
)

// RouteInterface is implemented for macOS and Linux. The Windows client
// learns its LAN adapter when it installs the route; doing it here would
// mean two parsers for two command languages, and #7 is where that belongs.
func RouteInterface(context.Context, Runner, netip.Prefix) (string, error) {
	return "", nil
}
