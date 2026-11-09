package main

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/Zane-SI/dotlink/internal/agent"
	"github.com/Zane-SI/dotlink/internal/proto"
)

func TestRoutesFlag(t *testing.T) {
	cases := []struct {
		name    string
		values  []string
		want    string
		wantErr string
	}{
		{
			name:   "comma separated",
			values: []string{"192.168.1.0/24,10.0.0.0/8"},
			want:   "192.168.1.0/24,10.0.0.0/8",
		},
		{
			name:   "repeated flag accumulates",
			values: []string{"192.168.1.0/24", "10.0.0.0/8"},
			want:   "192.168.1.0/24,10.0.0.0/8",
		},
		{
			name:   "comma list and repeat together",
			values: []string{"192.168.1.0/24,10.0.0.0/8", "172.16.0.0/12"},
			want:   "192.168.1.0/24,10.0.0.0/8,172.16.0.0/12",
		},
		{
			name:   "host bits are masked away",
			values: []string{"192.168.1.9/24"},
			want:   "192.168.1.0/24",
		},
		{
			name:   "whitespace is tolerated",
			values: []string{" 192.168.1.0/24 , 10.0.0.0/8 "},
			want:   "192.168.1.0/24,10.0.0.0/8",
		},
		{
			name:   "empty entries are skipped",
			values: []string{"192.168.1.0/24,,10.0.0.0/8"},
			want:   "192.168.1.0/24,10.0.0.0/8",
		},
		{
			name:    "invalid CIDR",
			values:  []string{"192.168.1.1"},
			wantErr: "is not a CIDR prefix",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r routesFlag
			var err error
			for _, v := range c.values {
				if err = r.Set(v); err != nil {
					break
				}
			}
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Set: %v", err)
			}
			if got := r.String(); got != c.want {
				t.Fatalf("String() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestUpFlagReachesTheDaemon(t *testing.T) {
	opts, err := parseUpFlags([]string{"--advertise-routes=192.168.1.9/24,10.0.0.0/8", "--relay-only"})
	if err != nil {
		t.Fatalf("parseUpFlags: %v", err)
	}
	d := upDaemon(opts, agent.State{}, slog.New(slog.DiscardHandler))
	if len(d.AdvertiseRoutes) != 2 ||
		d.AdvertiseRoutes[0].String() != "192.168.1.0/24" ||
		d.AdvertiseRoutes[1].String() != "10.0.0.0/8" {
		t.Fatalf("Daemon.AdvertiseRoutes = %v, want the two masked flags", d.AdvertiseRoutes)
	}
	if !d.NoPunch {
		t.Fatal("--relay-only did not reach the Daemon")
	}
}

func TestPrintNodesShowsRoutes(t *testing.T) {
	pm := &proto.PeerMap{
		Self: proto.Self{Hostname: "me", IPv4: "100.64.0.1"},
		Peers: []proto.Node{{
			Hostname:     "gateway",
			IPv4:         "100.64.0.2",
			SubnetRoutes: []string{"192.168.1.0/24"},
		}},
	}
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	printNodes(pm)
	_ = w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "ROUTES") || !strings.Contains(string(out), "192.168.1.0/24") {
		t.Fatalf("nodes output does not show the advertised route:\n%s", out)
	}
}
