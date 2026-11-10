//go:build linux

package netshare

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type linuxRunner struct {
	calls  []string
	fail   map[string]error
	output map[string]string
	exist  map[string]bool
}

func (r *linuxRunner) Run(_ context.Context, name string, args ...string) error {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if r.exist != nil && strings.Contains(call, " -C ") && r.exist[call] {
		return nil
	}
	if strings.Contains(call, " -C ") {
		return errors.New("exit status 1")
	}
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
	return "", errors.New("Network is unreachable")
}

func linuxRoutes() map[string]string {
	return map[string]string{
		"ip route get 192.168.1.0/24": "192.168.1.0 dev eth0 src 192.168.1.5 uid 0\n",
		"ip -6 route get fd00:1::/64": "fd00:1:: dev eth0 src fd00::1 uid 0\n",
	}
}

func TestEnableLinuxInstallsAndRemovesRules(t *testing.T) {
	r := &linuxRunner{output: linuxRoutes()}
	cleanup, err := Enable(context.Background(), r, Config{
		TUN:     "dotlink",
		Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Sources: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
	})
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	joined := strings.Join(r.calls, "\n")
	for _, want := range []string{
		"sysctl -w net.ipv4.ip_forward=1",
		"iptables -w -t nat -A POSTROUTING -s 100.64.0.0/10 -o eth0 -m comment --comment dotlink-subnet-router -j MASQUERADE",
		"iptables -w -I FORWARD 1 -i dotlink -o eth0 -m comment --comment dotlink-subnet-router -j ACCEPT",
		"iptables -w -I FORWARD 1 -i eth0 -o dotlink -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment dotlink-subnet-router -j ACCEPT",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
	cleanup()
	joined = strings.Join(r.calls, "\n")
	for _, want := range []string{
		"iptables -w -t nat -D POSTROUTING",
		"iptables -w -D FORWARD -i dotlink -o eth0",
		"iptables -w -D FORWARD -i eth0 -o dotlink",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("cleanup missing %q in:\n%s", want, joined)
		}
	}
}

func TestEnableLinuxHandlesIPv6(t *testing.T) {
	r := &linuxRunner{output: linuxRoutes()}
	_, err := Enable(context.Background(), r, Config{
		TUN:    "dotlink",
		Routes: []netip.Prefix{netip.MustParsePrefix("fd00:1::/64")},
	})
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	joined := strings.Join(r.calls, "\n")
	for _, want := range []string{
		"sysctl -w net.ipv4.ip_forward=1",
		"sysctl -w net.ipv6.conf.all.forwarding=1",
		"ip6tables -w -t nat -A POSTROUTING -s fd00::/64 -o eth0",
		"ip6tables -w -I FORWARD 1 -i dotlink -o eth0",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestEnableLinuxRefusesUnreachableLANAndLoop(t *testing.T) {
	p := netip.MustParsePrefix("192.168.1.0/24")
	r := &linuxRunner{output: map[string]string{}}
	if _, err := Enable(context.Background(), r, Config{TUN: "dotlink", Routes: []netip.Prefix{p}, Sources: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}}); err == nil || !strings.Contains(err.Error(), "no route to") {
		t.Fatalf("unreachable LAN err = %v", err)
	}
	r = &linuxRunner{output: map[string]string{"ip route get 192.168.1.0/24": "192.168.1.0 dev dotlink src 100.64.0.1\n"}}
	if _, err := Enable(context.Background(), r, Config{TUN: "dotlink", Routes: []netip.Prefix{p}, Sources: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}}); err == nil || !strings.Contains(err.Error(), "would loop") {
		t.Fatalf("loop err = %v", err)
	}
}

func TestEnableLinuxDoesNotDeleteAPreexistingRuleTwice(t *testing.T) {
	r := &linuxRunner{output: linuxRoutes(), exist: map[string]bool{
		"iptables -w -t nat -C POSTROUTING -s 100.64.0.0/10 -o eth0 -m comment --comment dotlink-subnet-router -j MASQUERADE": true,
	}}
	cleanup, err := Enable(context.Background(), r, Config{
		TUN:     "dotlink",
		Routes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Sources: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
	})
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	joined := strings.Join(r.calls, "\n")
	if strings.Contains(joined, "-A POSTROUTING") {
		t.Fatalf("added an existing NAT rule:\n%s", joined)
	}
	cleanup()
	if !strings.Contains(strings.Join(r.calls, "\n"), "-D POSTROUTING") {
		t.Fatalf("cleanup did not remove the rule it recognised")
	}
}
