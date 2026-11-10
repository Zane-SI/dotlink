//go:build darwin

package netcfg

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

type recorder struct {
	cmds   [][]string
	fail   map[string]error
	routes map[string]string // full command → interface
}

func (r *recorder) Run(_ context.Context, name string, args ...string) error {
	full := append([]string{name}, args...)
	r.cmds = append(r.cmds, full)
	for prefix, err := range r.fail {
		if strings.HasPrefix(strings.Join(full, " "), prefix) {
			return err
		}
	}
	return nil
}

// Output answers route lookups from a canned table: tests care about the
// decision, not about parsing two platform dialects.
func (r *recorder) Output(_ context.Context, name string, args ...string) (string, error) {
	full := append([]string{name}, args...)
	r.cmds = append(r.cmds, full)
	if r.routes == nil {
		return "", nil
	}
	if iface, ok := r.routes[strings.Join(full, " ")]; ok {
		return "  route to: 192.168.1.0\n  interface: " + iface + "\n", nil
	}
	return "route: writing to routing socket: not in table\n", fmt.Errorf("exit status 1")
}

func (r *recorder) joined() []string {
	out := make([]string, len(r.cmds))
	for i, c := range r.cmds {
		out[i] = strings.Join(c, " ")
	}
	return out
}

func TestConfigureSetsMTUFirstThenAddressThenRoutes(t *testing.T) {
	r := &recorder{}
	cfg := Config{
		Name:    "utun5",
		IPv4:    netip.MustParseAddr("100.64.0.1"),
		IPv4Net: netip.MustParsePrefix("100.64.0.0/10"),
		IPv6:    netip.MustParseAddr("fd00::1"),
		IPv6Net: netip.MustParsePrefix("fd00::/64"),
		MTU:     1280,
		Routes: []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("fd00:1::/64"),
		},
	}
	if err := Configure(context.Background(), r, cfg); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	want := []string{
		"ifconfig utun5 mtu 1280",
		"ifconfig utun5 inet 100.64.0.1 100.64.0.1 netmask 255.192.0.0 up",
		"ifconfig utun5 inet6 fd00::1 prefixlen 64",
		"route -n add -net 192.168.1.0/24 -interface utun5",
		"route -n add -inet6 fd00:1::/64 -interface utun5",
	}
	got := r.joined()
	if len(got) != len(want) {
		t.Fatalf("ran %d commands, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestConfigureStopsAtTheFirstFailure(t *testing.T) {
	r := &recorder{fail: map[string]error{"route": fmt.Errorf("route: permission denied")}}
	cfg := Config{
		Name:    "utun5",
		IPv4:    netip.MustParseAddr("100.64.0.1"),
		IPv4Net: netip.MustParsePrefix("100.64.0.0/10"),
		Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}
	err := Configure(context.Background(), r, cfg)
	if err == nil {
		t.Fatal("Configure succeeded with a failing route")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error does not say what happened: %v", err)
	}
	if len(r.cmds) != 3 {
		t.Fatalf("kept going after a failure: %v", r.joined())
	}
}

func TestConfigureTreatsAnExistingRouteAsSuccess(t *testing.T) {
	// A route left behind by a previous session is still the route we wanted:
	// failing the whole session every two seconds on "File exists" kept the
	// Agent from ever coming up.
	r := &recorder{fail: map[string]error{
		"route -n add -net 192.168.1.0/24": fmt.Errorf("exit status 1: add net 192.168.1.0: gateway utun5: File exists"),
	}}
	cfg := Config{
		Name:    "utun5",
		IPv4:    netip.MustParseAddr("100.64.0.1"),
		IPv4Net: netip.MustParsePrefix("100.64.0.0/10"),
		Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}
	if err := Configure(context.Background(), r, cfg); err != nil {
		t.Fatalf("Configure: %v", err)
	}
}

func TestConfigureNeedsAnInterface(t *testing.T) {
	if err := Configure(context.Background(), &recorder{}, Config{}); err == nil {
		t.Fatal("configured an unnamed interface")
	}
}

func TestNetmask(t *testing.T) {
	cases := map[string]string{
		"100.64.0.0/10":  "255.192.0.0",
		"10.0.0.0/8":     "255.0.0.0",
		"192.168.0.0/16": "255.255.0.0",
		"192.168.1.0/24": "255.255.255.0",
		"10.1.2.3/32":    "255.255.255.255",
		"0.0.0.0/0":      "0.0.0.0",
		"10.0.0.0/12":    "255.240.0.0",
		"10.0.0.0/30":    "255.255.255.252",
		"10.0.0.0/25":    "255.255.255.128",
	}
	for in, want := range cases {
		if got := netmask(netip.MustParsePrefix(in)); got != want {
			t.Errorf("netmask(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestDefaultMTU(t *testing.T) {
	r := &recorder{}
	cfg := Config{Name: "utun0", IPv4: netip.MustParseAddr("100.64.0.1"), IPv4Net: netip.MustParsePrefix("100.64.0.0/10")}
	if err := Configure(context.Background(), r, cfg); err != nil {
		t.Fatal(err)
	}
	if got := r.joined()[0]; got != "ifconfig utun0 mtu 1280" {
		t.Fatalf("mtu command = %q", got)
	}
}

func TestAddRouteTreatsAnExistingRouteAsSuccess(t *testing.T) {
	// route(8) reports "File exists" when the LAN is already routed at the
	// TUN, which is what a second reconcile of the same map does.
	r := &recorder{fail: map[string]error{
		"route -n add -net 192.168.1.0/24": fmt.Errorf("exit status 1: add net 192.168.1.0: gateway utun5: File exists"),
	}}
	if err := AddRoute(context.Background(), r, "utun5", netip.MustParsePrefix("192.168.1.0/24")); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
}

func TestDeleteRouteTreatsAMissingRouteAsSuccess(t *testing.T) {
	r := &recorder{fail: map[string]error{
		"route -n delete -net 10.0.0.0/8": fmt.Errorf("exit status 1: route: writing to routing socket: not in table"),
	}}
	if err := DeleteRoute(context.Background(), r, "utun5", netip.MustParsePrefix("10.0.0.0/8")); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
}

func TestAddRouteReportsARealFailure(t *testing.T) {
	// Only the two idempotency cases are answers. Anything else is a broken
	// route table and must not be reported as a clean reconcile.
	r := &recorder{fail: map[string]error{
		"route -n add -net 192.168.1.0/24": fmt.Errorf("exit status 1: route: permission denied"),
	}}
	err := AddRoute(context.Background(), r, "utun5", netip.MustParsePrefix("192.168.1.0/24"))
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err = %v, want a permission error", err)
	}
}

func TestAddAndDeleteRoute(t *testing.T) {
	r := &recorder{}
	v4 := netip.MustParsePrefix("192.168.1.9/24")
	v6 := netip.MustParsePrefix("2001:db8:1::/64")
	for _, pr := range []netip.Prefix{v4, v6} {
		if err := AddRoute(context.Background(), r, "utun5", pr); err != nil {
			t.Fatalf("AddRoute %s: %v", pr, err)
		}
		if err := DeleteRoute(context.Background(), r, "utun5", pr); err != nil {
			t.Fatalf("DeleteRoute %s: %v", pr, err)
		}
	}
	want := []string{
		"route -n add -net 192.168.1.0/24 -interface utun5",
		"route -n delete -net 192.168.1.0/24 -interface utun5",
		"route -n add -inet6 2001:db8:1::/64 -interface utun5",
		"route -n delete -inet6 2001:db8:1::/64 -interface utun5",
	}
	got := r.joined()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
