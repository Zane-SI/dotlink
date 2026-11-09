package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/Zane-SI/dotlink/internal/netcfg"
)

// lookup asks one of our own resolvers, the way the OS would after the
// /etc/resolver rule lands.
func lookup(t *testing.T, addr, name string) ([]string, error) {
	t.Helper()
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return r.LookupHost(ctx, name)
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// TestMagicDNSAnswersOverlayNames covers the two things a user notices: their
// own machine resolves, and a peer resolves to the Overlay address rather than
// to whatever the LAN DHCP server once handed out.
func TestMagicDNSAnswersOverlayNames(t *testing.T) {
	r := newRig(t)
	mini, miniHome := r.join(t, "mac-mini")
	book, bookHome := r.join(t, "macbook")

	port := freeUDPPort(t)
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	var (
		zone     string
		gotAddr  netip.Addr
		installs atomic.Int32
	)
	start(t, mini, miniHome)
	start(t, book, bookHome, func(d *Daemon) {
		d.DNSListen = "127.0.0.1"
		d.DNSPort = port
		d.ConfigureResolver = func(z string, a netip.Addr) (func(), error) {
			installs.Add(1)
			zone, gotAddr = z, a
			return func() {}, nil
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		names, err := lookup(t, dnsAddr, "mac-mini.dotlink")
		if err == nil && contains(names, mini.IPv4) {
			// LookupHost asks A and AAAA, so the answer carries both families;
			// the IPv4 one is what "the Overlay address" means here.
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mac-mini.dotlink never resolved: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	if zone != "dotlink" {
		t.Fatalf("zone = %q, want dotlink", zone)
	}
	if gotAddr != netip.MustParseAddr(book.IPv4) {
		t.Fatalf("resolver points at %s, want this Node's Overlay IP %s", gotAddr, book.IPv4)
	}
	if installs.Load() != 1 {
		t.Fatalf("resolver installed %d times, want 1", installs.Load())
	}

	// Our own name resolves too: that is what makes `ssh mac-mini.dotlink`
	// work from the machine itself.
	if names, err := lookup(t, dnsAddr, "macbook.dotlink"); err != nil || !contains(names, book.IPv4) {
		t.Fatalf("macbook.dotlink = %v, %v", names, err)
	}

	// A name nobody claimed is NXDOMAIN, so tools fail in milliseconds
	// instead of waiting for a connect timeout.
	if _, err := lookup(t, dnsAddr, "ghost.dotlink"); err == nil {
		t.Fatal("ghost.dotlink resolved, want NXDOMAIN")
	}

	// Anything outside the zone is refused rather than answered: the Agent
	// is not authoritative for the internet.
	if _, err := lookup(t, dnsAddr, "example.com"); err == nil {
		t.Fatal("example.com resolved from the Overlay resolver")
	}
}

// TestMagicDNSStopsResolvingRevokedNodes is the "immediately" in the
// acceptance criteria: a revoked Node must not keep answering for its TTL.
func TestMagicDNSStopsResolvingRevokedNodes(t *testing.T) {
	r := newRig(t)
	mini, miniHome := r.join(t, "mac-mini")
	book, bookHome := r.join(t, "macbook")

	port := freeUDPPort(t)
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	start(t, mini, miniHome)
	start(t, book, bookHome, func(d *Daemon) {
		d.DNSListen = "127.0.0.1"
		d.DNSPort = port
		d.ConfigureResolver = func(string, netip.Addr) (func(), error) { return func() {}, nil }
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		if names, err := lookup(t, dnsAddr, "mac-mini.dotlink"); err == nil && contains(names, mini.IPv4) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mac-mini.dotlink never resolved before revocation")
		}
		time.Sleep(50 * time.Millisecond)
	}

	req, err := http.NewRequest(http.MethodDelete, r.server.URL+"/v1/admin/nodes/"+mini.NodeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testAdmin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: status = %d", resp.StatusCode)
	}

	deadline = time.Now().Add(5 * time.Second)
	for {
		_, err := lookup(t, dnsAddr, "mac-mini.dotlink")
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("revoked Node still resolves after 5s: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestMagicDNSCleansUpItsResolverRule checks the disconnect path: the rule
// must be gone before the address it points at stops existing.
func TestMagicDNSCleansUpItsResolverRule(t *testing.T) {
	r := newRig(t)
	node, home := r.join(t, "mac-mini")
	ch := tuntest.NewChannelTUN()
	var removed atomic.Bool
	d := &Daemon{
		State:     node,
		Home:      home,
		UDPListen: "127.0.0.1:0",
		MakeTUN:   func(int) (tun.Device, error) { return ch.TUN(), nil },
		Configure: func(context.Context, netcfg.Config) error { return nil },
		DNSListen: "127.0.0.1",
		DNSPort:   freeUDPPort(t),
		ConfigureResolver: func(string, netip.Addr) (func(), error) {
			return func() { removed.Store(true) }, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	time.Sleep(300 * time.Millisecond)
	if removed.Load() {
		t.Fatal("cleanup ran before the session ended")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !removed.Load() {
		t.Fatal("disconnect left the resolver rule behind")
	}
}
