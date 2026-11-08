package netcfg

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

type recorder struct {
	cmds [][]string
	fail map[string]error
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
