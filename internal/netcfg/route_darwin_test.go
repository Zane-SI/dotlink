//go:build darwin

package netcfg

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// outputRunner answers one route lookup with exactly what the test hands it.
type outputRunner struct {
	out   string
	err   error
	calls []string
}

func (r *outputRunner) Run(context.Context, string, ...string) error { return nil }

func (r *outputRunner) Output(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	return r.out, r.err
}

func TestRouteInterface(t *testing.T) {
	v4 := netip.MustParsePrefix("192.168.1.0/24")
	v6 := netip.MustParsePrefix("fd00:1::/64")
	cases := []struct {
		name    string
		prefix  netip.Prefix
		out     string
		err     error
		want    string
		wantErr string
		wantCmd string
	}{
		{
			name:    "names the egress interface",
			prefix:  v4,
			out:     "   route to: 192.168.1.0\n  interface: en0\n",
			want:    "en0",
			wantCmd: "route -n get -net 192.168.1.0/24",
		},
		{
			// An IPv6 lookup without -inet6 is answered with the IPv4
			// default route, which would point NAT at the wrong NIC.
			name:    "an ipv6 prefix is looked up as inet6",
			prefix:  v6,
			out:     "   route to: fd00:1::\n  interface: en0\n",
			want:    "en0",
			wantCmd: "route -n get -inet6 fd00:1::/64",
		},
		{
			// route(8) exits non-zero for a prefix it has no route to. That is
			// an answer, not a failure: the caller must be able to say "this
			// Mac cannot reach that LAN" without a command error.
			name:    "not in table means no route",
			prefix:  v4,
			out:     "route: writing to routing socket: not in table\n",
			err:     errExitStatus,
			wantCmd: "route -n get -net 192.168.1.0/24",
		},
		{
			name:    "a real failure says what happened",
			prefix:  v4,
			out:     "route: writing to routing socket: permission denied\n",
			err:     errExitStatus,
			wantErr: "permission denied",
			wantCmd: "route -n get -net 192.168.1.0/24",
		},
		{
			name:    "success without an interface line means no route",
			prefix:  v4,
			out:     "route to: 192.168.1.0\n",
			wantCmd: "route -n get -net 192.168.1.0/24",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &outputRunner{out: c.out, err: c.err}
			got, err := RouteInterface(context.Background(), r, c.prefix)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("RouteInterface: %v", err)
				}
				if got != c.want {
					t.Fatalf("interface = %q, want %q", got, c.want)
				}
			}
			if len(r.calls) != 1 || r.calls[0] != c.wantCmd {
				t.Fatalf("lookup command = %v, want %s", r.calls, c.wantCmd)
			}
		})
	}
}

type exitStatus string

func (e exitStatus) Error() string { return string(e) }

const errExitStatus = exitStatus("exit status 1")

type existingRouteRunner struct {
	iface string
	err   error
}

func (r *existingRouteRunner) Run(context.Context, string, ...string) error {
	return r.err
}

func (r *existingRouteRunner) Output(context.Context, string, ...string) (string, error) {
	return "  interface: " + r.iface + "\n", nil
}

func TestAddRouteRefusesToShadowAnotherInterfacesRoute(t *testing.T) {
	r := &existingRouteRunner{
		iface: "en0",
		err:   exitStatus("exit status 1: add net 192.168.1.0: gateway utun5: File exists"),
	}
	err := AddRoute(context.Background(), r, "utun5", netip.MustParsePrefix("192.168.1.0/24"))
	if err == nil || !strings.Contains(err.Error(), "already exists on en0") {
		t.Fatalf("err = %v, want a refusal naming en0", err)
	}
}

func TestAddRouteAcceptsAnExistingRouteOnTheSameTUN(t *testing.T) {
	r := &existingRouteRunner{
		iface: "utun5",
		err:   exitStatus("exit status 1: add net 192.168.1.0: gateway utun5: File exists"),
	}
	if err := AddRoute(context.Background(), r, "utun5", netip.MustParsePrefix("192.168.1.0/24")); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
}
