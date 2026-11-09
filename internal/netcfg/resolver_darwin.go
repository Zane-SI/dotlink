//go:build darwin

package netcfg

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

// resolverDir is where macOS looks for per-domain DNS configuration.
const resolverDir = "/etc/resolver"

// WriteResolver points one domain at the Agent's own Overlay IP.
//
// This is split-DNS, not a global DNS change: macOS resolves example.com
// exactly as before, and only names under this domain are sent to us. The
// returned func removes the file, so a disconnect leaves no rule pointing at
// an address that no longer exists.
func WriteResolver(zone string, addr netip.Addr) (func(), error) {
	if zone == "" {
		return func() {}, nil
	}
	if !addr.IsValid() {
		return func() {}, nil
	}
	if err := os.MkdirAll(resolverDir, 0o755); err != nil {
		return nil, fmt.Errorf("magicdns: create %s: %w", resolverDir, err)
	}
	path := filepath.Join(resolverDir, zone)
	tmp, err := os.CreateTemp(resolverDir, ".dotlink-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	content := fmt.Sprintf("nameserver %s\nsearch_order 1\n", addr)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, err
	}
	// The file is read by the resolver daemon (unprivileged); 0644 matches
	// the other files in /etc/resolver.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		os.Remove(tmpName)
		return nil, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("magicdns: install %s: %w", path, err)
	}
	remove := func() {
		// Leaving the file behind after a disconnect would make every later
		// lookup wait on a dead address.
		_ = os.Remove(path)
	}
	return remove, nil
}
