//go:build !darwin

package netcfg

import "net/netip"

// WriteResolver is a no-op off macOS: Windows configures its NRPT rules in
// the Windows client, and iOS hands NEDNSSettings to the system. Both are
// separate tickets; doing nothing here keeps the Agent honest instead of
// pretending it configured something.
func WriteResolver(string, netip.Addr) (func(), error) {
	return func() {}, nil
}
