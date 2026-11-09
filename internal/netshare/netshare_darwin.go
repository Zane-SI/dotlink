//go:build darwin

package netshare

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Zane-SI/dotlink/internal/netcfg"
)

// anchor is the pf anchor name. It lives under com.apple/ because that is the
// only place a stock /etc/pf.conf looks: its anchor points are
// `anchor "com.apple/*"` and `load anchor "com.apple" from ...`, so a
// com.dotlink anchor would be loaded and then never evaluated — the NAT rules
// would silently do nothing. Everything we install lives under this anchor, so
// disabling Subnet Router is one `-F all` and cannot touch the user's rules.
const anchor = "com.apple/dotlink"

// Enable turns the machine into a gateway and returns the cleanup.
//
// The steps are the ones a human would type: turn on forwarding, write a pf
// anchor that NATs the Overlay ranges out of each LAN interface, load it,
// enable pf. Ordering matters — enabling pf before the anchor exists is the
// one way to block traffic the user did not ask us to touch.
func Enable(ctx context.Context, r netcfg.Runner, c Config) (func(), error) {
	// A previous run may have crashed after `pfctl -E` but before cleanup.
	// Release that reference before taking a new one.
	if c.TokenPath != "" {
		releaseStaleToken(ctx, r, c.TokenPath)
	}
	if len(c.Routes) == 0 {
		return func() {}, nil
	}
	ifaces := make([]string, 0, len(c.Routes))
	for _, pr := range c.Routes {
		if pr.Bits() == 0 {
			return nil, fmt.Errorf("%s is a default route; exit nodes are not in v1", pr)
		}
		iface, err := netcfg.RouteInterface(ctx, r, pr)
		if err != nil {
			return nil, err
		}
		if iface == "" {
			// Advertising a LAN this Mac cannot reach would black-hole every
			// peer's traffic to it, and the peers would blame the tunnel.
			return nil, fmt.Errorf("no route to %s from this machine; run the Gateway on that LAN or add a static route first", pr)
		}
		if c.TUN != "" && iface == c.TUN {
			return nil, fmt.Errorf("%s already routes into %s; forwarding it back into the tunnel would loop", pr, c.TUN)
		}
		ifaces = append(ifaces, iface)
	}
	ifaces = uniq(ifaces)

	sources := c.Sources
	if sources == nil {
		sources = DefaultSources()
	}
	v4, v6 := splitByFamily(sources)

	// Forwarding is global to the machine. Restoring the old value on
	// disconnect would need a sysctl read; leaving it on is the smaller lie
	// than flipping it under another VPN's feet.
	if err := r.Run(ctx, "sysctl", "-w", "net.inet.ip.forwarding=1"); err != nil {
		return nil, fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	if len(v6) > 0 {
		if err := r.Run(ctx, "sysctl", "-w", "net.inet6.ip6.forwarding=1"); err != nil {
			return nil, fmt.Errorf("enable IPv6 forwarding: %w", err)
		}
	}

	dir, private, err := rulesDir(c.RuleDir)
	if err != nil {
		return nil, err
	}
	removeRules := func() {
		if private {
			_ = os.RemoveAll(dir)
			return
		}
		_ = os.Remove(filepath.Join(dir, "dotlink-pf.conf"))
	}

	path := filepath.Join(dir, "dotlink-pf.conf")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		removeRules()
		return nil, fmt.Errorf("write pf rules: %w", err)
	}
	if _, err := f.WriteString(pfRules(ifaces, v4, v6)); err != nil {
		f.Close()
		removeRules()
		return nil, fmt.Errorf("write pf rules: %w", err)
	}
	if err := f.Close(); err != nil {
		removeRules()
		return nil, fmt.Errorf("write pf rules: %w", err)
	}
	if err := r.Run(ctx, "pfctl", "-a", anchor, "-f", path); err != nil {
		removeRules()
		return nil, fmt.Errorf("load pf rules: %w", err)
	}
	// -E enables pf and prints a reference token. pf keeps a reference count,
	// so leaving the token behind means pf can never be turned off again; the
	// matching release is `-X <token>`.
	out, err := r.Output(ctx, "pfctl", "-E")
	token := pfToken(out)
	if err != nil {
		// -E can bump pf's reference count and still exit non-zero. When it
		// printed a token, that count is ours to give back, or pf can never be
		// turned off again.
		if token != "" {
			_ = r.Run(context.Background(), "pfctl", "-X", token)
		}
		// A half-enabled pf is worse than none: remove what we loaded before
		// reporting, or the anchor keeps NATting with no owner.
		_ = r.Run(context.Background(), "pfctl", "-a", anchor, "-F", "all")
		removeRules()
		return nil, fmt.Errorf("enable pf: %w", err)
	}
	if token == "" {
		// -E succeeded but printed no token we can release. Treating that as
		// success leaks pf's reference count: every later `-E` bumps it and
		// nothing can ever bring pf back down. The anchor is ours to remove.
		_ = r.Run(context.Background(), "pfctl", "-a", anchor, "-F", "all")
		removeRules()
		return nil, fmt.Errorf("enable pf: pfctl -E returned no reference token; refusing to leak it")
	}
	if c.TokenPath != "" {
		if err := os.WriteFile(c.TokenPath, []byte(token+"\n"), 0o600); err != nil {
			// The token exists only in this process now. Release it before
			// returning, or the failed start leaks pf's reference count.
			_ = r.Run(context.Background(), "pfctl", "-X", token)
			_ = r.Run(context.Background(), "pfctl", "-a", anchor, "-F", "all")
			removeRules()
			return nil, fmt.Errorf("record pf token: %w", err)
		}
	}

	return func() {
		// Flush our anchor only: the user's own pf rules are not ours to
		// remove.
		_ = r.Run(context.Background(), "pfctl", "-a", anchor, "-F", "all")
		if token != "" {
			_ = r.Run(context.Background(), "pfctl", "-X", token)
		}
		if c.TokenPath != "" {
			_ = os.Remove(c.TokenPath)
		}
		removeRules()
	}, nil
}

// releaseStaleToken releases a token recorded by a previous process. It is
// best-effort: a stale or already-released token must not block a new start.
func releaseStaleToken(ctx context.Context, r netcfg.Runner, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	token := strings.TrimSpace(string(data))
	if token != "" && tokenPattern.MatchString(token) {
		_ = r.Run(ctx, "pfctl", "-X", token)
	}
	_ = os.Remove(path)
}

// rulesDir picks where the anchor file lives. A root process writing a fixed
// path in /tmp would follow any symlink a local user placed there, so the
// default is a fresh 0700 directory that only root can enter. Tests pass
// RuleDir and keep the fixed filename inside their own temp directory.
func rulesDir(configured string) (dir string, private bool, err error) {
	if configured != "" {
		return configured, false, nil
	}
	dir, err = os.MkdirTemp("", "dotlink-pf-")
	if err != nil {
		return "", false, fmt.Errorf("create pf rules directory: %w", err)
	}
	return dir, true, nil
}

// pfTokenPattern pulls the number out of `pfctl -E`'s "Token : 1234567890".
var pfTokenPattern = regexp.MustCompile(`(?m)^Token\s*:\s*(\d+)\s*$`)
var tokenPattern = regexp.MustCompile(`^\d+$`)

// pfToken returns the reference token pfctl printed, or "" when the output
// has no token to release.
func pfToken(out string) string {
	if m := pfTokenPattern.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// LANInterfaceOf is a helper for status output and for the conflict message.
func LANInterfaceOf(ctx context.Context, r netcfg.Runner, pr netip.Prefix) (string, error) {
	return netcfg.RouteInterface(ctx, r, pr)
}
