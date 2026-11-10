//go:build linux

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

type linuxRunner struct {
	calls  []string
	fail   map[string]error
	output map[string]string
}

func (r *linuxRunner) Run(_ context.Context, name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if err, ok := r.fail[call]; ok {
		return err
	}
	return nil
}

func (r *linuxRunner) Output(_ context.Context, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if out, ok := r.output[call]; ok {
		return out, nil
	}
	return "", errors.New("no route to host")
}

func TestConfigureLinuxUsesIPRoute2(t *testing.T) {
	r := &linuxRunner{}
	err := Configure(context.Background(), r, Config{
		Name:    "dotlink",
		IPv4:    netip.MustParseAddr("100.64.0.1"),
		IPv4Net: netip.MustParsePrefix("100.64.0.0/10"),
		IPv6:    netip.MustParseAddr("fd00::1"),
		IPv6Net: netip.MustParsePrefix("fd00::/64"),
		MTU:     1280,
		Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	want := []string{
		"ip link set dev dotlink mtu 1280 up",
		"ip addr replace 100.64.0.1/10 dev dotlink",
		"ip -6 addr replace fd00::1/64 dev dotlink",
		"ip route add 192.168.1.0/24 dev dotlink",
	}
	if strings.Join(r.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(r.calls, "\n"), strings.Join(want, "\n"))
	}
}

func TestAddRouteLinuxRefusesAnotherInterfacesRoute(t *testing.T) {
	p := netip.MustParsePrefix("192.168.1.0/24")
	r := &linuxRunner{
		fail:   map[string]error{"ip route add 192.168.1.0/24 dev dotlink": fmt.Errorf("RTNETLINK answers: File exists")},
		output: map[string]string{"ip route get 192.168.1.0/24": "192.168.1.0 dev eth0 src 192.168.1.5 uid 0\n"},
	}
	err := AddRoute(context.Background(), r, "dotlink", p)
	if err == nil || !strings.Contains(err.Error(), "already exists on eth0, not dotlink") {
		t.Fatalf("err = %v, want refusal naming eth0", err)
	}
}

func TestAddRouteLinuxAcceptsSameTUNRoute(t *testing.T) {
	p := netip.MustParsePrefix("192.168.1.0/24")
	r := &linuxRunner{
		fail:   map[string]error{"ip route add 192.168.1.0/24 dev dotlink": fmt.Errorf("RTNETLINK answers: File exists")},
		output: map[string]string{"ip route get 192.168.1.0/24": "192.168.1.0 dev dotlink src 100.64.0.1 uid 0\n"},
	}
	if err := AddRoute(context.Background(), r, "dotlink", p); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
}

func TestDeleteRouteLinuxTreatsMissingAsSuccess(t *testing.T) {
	r := &linuxRunner{fail: map[string]error{"ip route del 10.0.0.0/8 dev dotlink": fmt.Errorf("RTNETLINK answers: No such process")}}
	if err := DeleteRoute(context.Background(), r, "dotlink", netip.MustParsePrefix("10.0.0.0/8")); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
}

func TestRouteInterfaceLinuxIPv6(t *testing.T) {
	r := &linuxRunner{output: map[string]string{"ip -6 route get fd00:1::/64": "fd00:1:: dev eth0 src fd00::1 uid 0\n"}}
	iface, err := RouteInterface(context.Background(), r, netip.MustParsePrefix("fd00:1::/64"))
	if err != nil || iface != "eth0" {
		t.Fatalf("RouteInterface = %q, %v; want eth0", iface, err)
	}
}
