// Package netcfg puts the overlay addresses and routes on the TUN device.
//
// It shells out to ifconfig and route for the same reason wg-quick does:
// the ioctl path is per-platform and easy to get subtly wrong, while the
// command line is stable, visible in `ps`, and trivial to reproduce by hand
// when something goes wrong at 2am.
package netcfg

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// Runner runs one command. Tests substitute a recorder.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) error
}

// ExecRunner runs real commands.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Config is what the TUN needs before WireGuard can carry traffic.
type Config struct {
	Name    string       // utun5, wintun, ...
	IPv4    netip.Addr   // this Node's overlay address
	IPv4Net netip.Prefix // the overlay pool, 100.64.0.0/10
	IPv6    netip.Addr
	IPv6Net netip.Prefix
	MTU     int
	Routes  []netip.Prefix // extra prefixes routed at peers (Subnet Router)
}

func (c Config) mtu() int {
	if c.MTU == 0 {
		return 1280
	}
	return c.MTU
}

// Configure applies the addresses, the MTU and the routes.
//
// Order matters: the interface has to be up with its address before routes can
// point at it, and the MTU has to be set before the first packet, because
// WireGuard sizes its buffers from it.
func Configure(ctx context.Context, r Runner, c Config) error {
	if c.Name == "" {
		return fmt.Errorf("netcfg: no interface name")
	}
	steps := [][]string{
		{"ifconfig", c.Name, "mtu", fmt.Sprint(c.mtu())},
		{"ifconfig", c.Name, "inet", c.IPv4.String(), c.IPv4.String(), "netmask", netmask(c.IPv4Net), "up"},
	}
	if c.IPv6.IsValid() {
		steps = append(steps, []string{"ifconfig", c.Name, "inet6", c.IPv6.String(), "prefixlen", fmt.Sprint(c.IPv6Net.Bits())})
	}
	for _, p := range c.Routes {
		steps = append(steps, routeAdd(c.Name, p))
	}
	for _, s := range steps {
		if err := r.Run(ctx, s[0], s[1:]...); err != nil {
			return fmt.Errorf("netcfg: %w", err)
		}
	}
	return nil
}

func routeAdd(iface string, p netip.Prefix) []string {
	args := []string{"-n", "add"}
	if p.Addr().Is4() {
		args = append(args, "-net", p.String())
	} else {
		args = append(args, "-inet6", p.String())
	}
	return append([]string{"route"}, append(args, "-interface", iface)...)
}

// netmask renders a prefix as a dotted netmask, which is the only form
// macOS ifconfig accepts for IPv4.
func netmask(p netip.Prefix) string {
	if !p.IsValid() || !p.Addr().Is4() {
		return "255.255.255.255"
	}
	m := netip.AddrFrom4([4]byte{})
	var b [4]byte
	bits := p.Bits()
	for i := 0; i < 4; i++ {
		switch {
		case bits >= 8*(i+1):
			b[i] = 0xff
		case bits <= 8*i:
			b[i] = 0
		default:
			b[i] = byte(0xff << (8 - (bits - 8*i)))
		}
	}
	m = netip.AddrFrom4(b)
	return m.String()
}
