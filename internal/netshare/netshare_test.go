//go:build darwin

package netshare

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	cmds      []string
	routes    map[string]string // "route -n get -net 192.168.1.0/24" → en0
	enableOut string            // what `pfctl -E` prints; empty means the normal token
	fail      map[string]error  // full command → error, for both Run and Output
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) error {
	full := strings.Join(append([]string{name}, args...), " ")
	f.cmds = append(f.cmds, full)
	return f.fail[full]
}

func (f *fakeRunner) Output(_ context.Context, name string, args ...string) (string, error) {
	full := strings.Join(append([]string{name}, args...), " ")
	f.cmds = append(f.cmds, full)
	if err := f.fail[full]; err != nil {
		// pfctl -E increments the reference count before it can fail, so a
		// failing -E may still have printed a token that needs releasing.
		if full == "pfctl -E" {
			return f.enableOut, err
		}
		return "", err
	}
	if full == "pfctl -E" {
		if f.enableOut != "" {
			return f.enableOut, nil
		}
		return "pf enabled\nToken : 424242\n", nil
	}
	if iface, ok := f.routes[full]; ok {
		return "  route to: 192.168.1.0\n  interface: " + iface + "\n", nil
	}
	return "route: writing to routing socket: not in table\n", errNotInTable
}

type errString string

func (e errString) Error() string { return string(e) }

const errNotInTable = errString("exit status 1")

func (f *fakeRunner) has(prefix string) bool {
	for _, c := range f.cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestPFRulesNATBothFamilies(t *testing.T) {
	got := pfRules([]string{"en0"}, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}, []netip.Prefix{netip.MustParsePrefix("fd00::/64")})
	for _, want := range []string{
		"nat on en0 inet from 100.64.0.0/10 to any -> (en0)",
		"pass out quick on en0 inet from 100.64.0.0/10 to any keep state",
		"nat on en0 inet6 from fd00::/64 to any -> (en0)",
		"pass out quick on en0 inet6 from fd00::/64 to any keep state",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rules missing %q:\n%s", want, got)
		}
	}
}

func TestEnableNATsEachLANInterfaceOnce(t *testing.T) {
	dir := t.TempDir()
	f := &fakeRunner{routes: map[string]string{
		"route -n get -net 192.168.1.0/24": "en0",
		"route -n get -net 10.0.0.0/24":    "en0",
	}}
	stop, err := Enable(context.Background(), f, Config{
		TUN:     "utun5",
		Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("10.0.0.0/24")},
		RuleDir: dir,
	})
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}

	if !f.has("sysctl -w net.inet.ip.forwarding=1") {
		t.Fatalf("IPv4 forwarding was never enabled: %v", f.cmds)
	}
	// The default Sources include the IPv6 Overlay pool, so NAT rules for it
	// are written; forwarding must be on or those packets are dropped.
	if !f.has("sysctl -w net.inet6.ip6.forwarding=1") {
		t.Fatalf("IPv6 forwarding was never enabled: %v", f.cmds)
	}
	if n := strings.Count(strings.Join(f.cmds, "\n"), "nat on en0"); n != 0 {
		t.Fatalf("rules went on the command line, not through an anchor file")
	}
	iface, err := LANInterfaceOf(context.Background(), f, netip.MustParsePrefix("192.168.1.0/24"))
	if err != nil || iface != "en0" {
		t.Fatalf("LANInterfaceOf = %q, %v", iface, err)
	}

	rules, err := os.ReadFile(filepath.Join(dir, "dotlink-pf.conf"))
	if err != nil {
		t.Fatalf("read rules: %v", err)
	}
	// Two LANs behind one NIC must produce one rule set: duplicate nat rules
	// make pf reject the whole anchor.
	if n := strings.Count(string(rules), "nat on en0 inet from"); n != 1 {
		t.Fatalf("got %d IPv4 nat rules, want 1:\n%s", n, rules)
	}
	if !f.has("pfctl -a " + anchor + " -f " + filepath.Join(dir, "dotlink-pf.conf")) {
		t.Fatalf("anchor was never loaded: %v", f.cmds)
	}
	// A com.dotlink anchor is never evaluated by /etc/pf.conf; the rules only
	// take effect under the com.apple/* wildcard anchor points.
	if !strings.HasPrefix(anchor, "com.apple/") {
		t.Fatalf("anchor %q is outside the com.apple/ wildcard, so pf never evaluates it", anchor)
	}
	if !f.has("pfctl -E") {
		t.Fatalf("pf was never enabled: %v", f.cmds)
	}

	stop()
	if !f.has("pfctl -a " + anchor + " -F all") {
		t.Fatalf("cleanup did not flush the anchor: %v", f.cmds)
	}
	// -E bumps pf's reference count; without -X, pf can never be disabled.
	if !f.has("pfctl -X 424242") {
		t.Fatalf("cleanup did not release the pf token: %v", f.cmds)
	}
	if _, err := os.Stat(filepath.Join(dir, "dotlink-pf.conf")); !os.IsNotExist(err) {
		t.Fatalf("rules file survived cleanup: %v", err)
	}
	// Forwarding is global and shared with other software. Cleanup must not
	// flip it back under another VPN's feet.
	for _, cmd := range f.cmds {
		if strings.Contains(cmd, "sysctl") && strings.Contains(cmd, "=0") {
			t.Fatalf("cleanup turned forwarding off: %q", cmd)
		}
	}
}

func TestEnableRollsBackWhenPFEnableFails(t *testing.T) {
	dir := t.TempDir()
	f := &fakeRunner{
		routes: map[string]string{"route -n get -net 192.168.1.0/24": "en0"},
		fail:   map[string]error{"pfctl -E": errString("pfctl: /dev/pf: Permission denied")},
	}
	_, err := Enable(context.Background(), f, Config{
		TUN:     "utun5",
		Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		RuleDir: dir,
	})
	if err == nil {
		t.Fatal("Enable succeeded with pfctl -E failing")
	}
	// The anchor was loaded before -E failed; leaving it would keep NATting
	// with no owner.
	if !f.has("pfctl -a " + anchor + " -F all") {
		t.Fatalf("failed enable left the anchor loaded: %v", f.cmds)
	}
	if _, err := os.Stat(filepath.Join(dir, "dotlink-pf.conf")); !os.IsNotExist(err) {
		t.Fatalf("rules file survived a failed enable: %v", err)
	}
	// -E never printed a token, so there is nothing to release.
	if f.has("pfctl -X") {
		t.Fatalf("released a token that was never issued: %v", f.cmds)
	}
}

func TestEnableReleasesATokenWhenPFEnableFails(t *testing.T) {
	dir := t.TempDir()
	f := &fakeRunner{
		routes:    map[string]string{"route -n get -net 192.168.1.0/24": "en0"},
		enableOut: "pf enabled\nToken : 999\n",
		fail:      map[string]error{"pfctl -E": errString("pfctl: DIOCSTART: File exists")},
	}
	_, err := Enable(context.Background(), f, Config{
		TUN:     "utun5",
		Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		RuleDir: dir,
	})
	if err == nil {
		t.Fatal("Enable succeeded with pfctl -E failing")
	}
	// The failed -E still printed a token, which means the reference count was
	// already bumped: leaving it behind makes pf impossible to turn off.
	if !f.has("pfctl -X 999") {
		t.Fatalf("failed enable leaked the pf token: %v", f.cmds)
	}
	if !f.has("pfctl -a " + anchor + " -F all") {
		t.Fatalf("failed enable left the anchor loaded: %v", f.cmds)
	}
	if _, err := os.Stat(filepath.Join(dir, "dotlink-pf.conf")); !os.IsNotExist(err) {
		t.Fatalf("rules file survived a failed enable: %v", err)
	}
}

func TestEnableRejectsAnUnparseablePFToken(t *testing.T) {
	dir := t.TempDir()
	f := &fakeRunner{
		routes:    map[string]string{"route -n get -net 192.168.1.0/24": "en0"},
		enableOut: "pf enabled\n",
	}
	_, err := Enable(context.Background(), f, Config{
		TUN:     "utun5",
		Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		RuleDir: dir,
	})
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("err = %v, want an error about the missing token", err)
	}
	if !f.has("pfctl -a " + anchor + " -F all") {
		t.Fatalf("failed enable left the anchor loaded: %v", f.cmds)
	}
	if _, err := os.Stat(filepath.Join(dir, "dotlink-pf.conf")); !os.IsNotExist(err) {
		t.Fatalf("rules file survived a failed enable: %v", err)
	}
}

func TestEnableRefusesALANThisMachineCannotReach(t *testing.T) {
	f := &fakeRunner{}
	_, err := Enable(context.Background(), f, Config{
		Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")},
		RuleDir: t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "no route to 192.168.50.0/24") {
		t.Fatalf("err = %v, want a no-route error", err)
	}
	if f.has("sysctl") {
		t.Fatalf("forwarding was enabled for a LAN we cannot reach: %v", f.cmds)
	}
}

func TestEnableRefusesARouteIntoTheTunnel(t *testing.T) {
	f := &fakeRunner{routes: map[string]string{"route -n get -net 192.168.1.0/24": "utun5"}}
	_, err := Enable(context.Background(), f, Config{
		TUN:     "utun5",
		Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		RuleDir: t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "would loop") {
		t.Fatalf("err = %v, want a loop error", err)
	}
}

func TestEnableDoesNothingWithoutRoutes(t *testing.T) {
	f := &fakeRunner{}
	stop, err := Enable(context.Background(), f, Config{})
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	stop()
	if len(f.cmds) != 0 {
		t.Fatalf("ran commands with no routes: %v", f.cmds)
	}
}

func TestEnableUsesAPrivateRulesDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	f := &fakeRunner{routes: map[string]string{"route -n get -net 192.168.1.0/24": "en0"}}
	stop, err := Enable(context.Background(), f, Config{
		Routes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	})
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}

	var path string
	for _, cmd := range f.cmds {
		if strings.HasPrefix(cmd, "pfctl -a "+anchor+" -f ") {
			path = strings.TrimPrefix(cmd, "pfctl -a "+anchor+" -f ")
		}
	}
	if path == "" {
		t.Fatalf("anchor was never loaded: %v", f.cmds)
	}
	dir := filepath.Dir(path)
	// Root must not write a fixed /tmp path: a local user could pre-place a
	// symlink there and get root to truncate any file it points at.
	if dir == root {
		t.Fatalf("rules went to the shared TMPDIR %q, not a private directory", dir)
	}
	if filepath.Dir(dir) != root || !strings.HasPrefix(filepath.Base(dir), "dotlink-pf-") {
		t.Fatalf("rules directory %q is not a fresh dotlink-pf-* dir under %q", dir, root)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat rules directory: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("rules directory mode = %o, want 0700", perm)
	}

	stop()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("cleanup left the rules directory behind: %v", err)
	}
}

func TestEnableReleasesATokenLeftByACrash(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "pf.token")
	if err := os.WriteFile(tokenPath, []byte("123\n"), 0o600); err != nil {
		t.Fatalf("seed stale token: %v", err)
	}
	f := &fakeRunner{routes: map[string]string{"route -n get -net 192.168.1.0/24": "en0"}}
	stop, err := Enable(context.Background(), f, Config{
		TUN:       "utun5",
		Routes:    []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		RuleDir:   dir,
		TokenPath: tokenPath,
	})
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !f.has("pfctl -X 123") {
		t.Fatalf("stale token was never released: %v", f.cmds)
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("read current token: %v", err)
	}
	if strings.TrimSpace(string(data)) != "424242" {
		t.Fatalf("recorded token = %q, want 424242", data)
	}
	stop()
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("token file survived cleanup: %v", err)
	}
	if !f.has("pfctl -X 424242") {
		t.Fatalf("cleanup did not release the current token: %v", f.cmds)
	}
}
