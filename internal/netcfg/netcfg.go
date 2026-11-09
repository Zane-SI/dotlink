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
	// Output is Run plus stdout. Route lookups need the answer, not just the
	// exit status; keeping it on the same interface means tests fake one
	// thing instead of two.
	Output(ctx context.Context, name string, args ...string) (string, error)
}

// ExecRunner runs real commands.
type ExecRunner struct{}

// Output returns what the command printed, even when it failed: `route -n
// get` reports "not in table" on stderr and exits non-zero, and the caller
// needs to tell "no route" apart from "route command missing".
func (ExecRunner) Output(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

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
	for _, s := range steps {
		if err := r.Run(ctx, s[0], s[1:]...); err != nil {
			return fmt.Errorf("netcfg: %w", err)
		}
	}
	// Routes go through AddRoute so a route that already exists is success, not
	// a dead session: a restart would otherwise fail on "File exists" forever.
	for _, p := range c.Routes {
		if err := AddRoute(ctx, r, c.Name, p); err != nil {
			return err
		}
	}
	return nil
}

// routeArgs is the one spelling both install and removal use: `route` takes
// -net for IPv4 and -inet6 for IPv6, and the destination must be masked or
// the kernel rejects the entry.
func routeArgs(action, iface string, p netip.Prefix) []string {
	args := []string{"-n", action}
	if p.Addr().Is4() {
		args = append(args, "-net", p.Masked().String())
	} else {
		args = append(args, "-inet6", p.Masked().String())
	}
	return append(args, "-interface", iface)
}

// AddRoute points a subnet the peers advertise at this Node's TUN. The map
// changes at runtime, so this is separate from the routes Configure installs
// at startup.
//
// The route already being there is success only when it points at our TUN:
// route(8) answers "File exists" and the goal of an add is that the route
// exists. If the kernel would use another interface, the LAN is already local
// (or another Gateway's), and shadowing it would silently send the traffic
// the wrong way; that is a clear error instead.
func AddRoute(ctx context.Context, r Runner, iface string, p netip.Prefix) error {
	if !p.IsValid() || iface == "" {
		return fmt.Errorf("netcfg: add route needs an interface and a prefix")
	}
	if err := r.Run(ctx, "route", routeArgs("add", iface, p)...); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "file exists") {
			existing, lookupErr := RouteInterface(ctx, r, p)
			if lookupErr != nil {
				return fmt.Errorf("netcfg: add route %s: route exists but its interface could not be read: %w", p, lookupErr)
			}
			if existing != "" && existing != iface {
				return fmt.Errorf("netcfg: route %s already exists on %s, not %s; refusing to shadow it", p, existing, iface)
			}
			return nil
		}
		return fmt.Errorf("netcfg: add route %s: %w", p, err)
	}
	return nil
}

// DeleteRoute removes a route AddRoute installed. A route that is already
// gone is success: the goal is that it is gone, and route(8) says "not in
// table" when there was nothing to remove.
func DeleteRoute(ctx context.Context, r Runner, iface string, p netip.Prefix) error {
	if !p.IsValid() || iface == "" {
		return fmt.Errorf("netcfg: delete route needs an interface and a prefix")
	}
	if err := r.Run(ctx, "route", routeArgs("delete", iface, p)...); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not in table") {
			return nil
		}
		return fmt.Errorf("netcfg: delete route %s: %w", p, err)
	}
	return nil
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
