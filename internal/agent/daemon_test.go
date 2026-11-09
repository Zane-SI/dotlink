package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/Zane-SI/dotlink/internal/control"
	"github.com/Zane-SI/dotlink/internal/derp"
	"github.com/Zane-SI/dotlink/internal/netcfg"
	"github.com/Zane-SI/dotlink/internal/netshare"
	"github.com/Zane-SI/dotlink/internal/proto"
	"github.com/Zane-SI/dotlink/internal/relay"
)

const testAdmin = "dlk_adm_daemon_test"

// rig is one Control Plane plus one Relay, both on loopback.
type rig struct {
	server *httptest.Server
	relay  *net.UDPConn
	addr   netip.AddrPort
	secret string

	derpAddr string
	derpTLS  *tls.Config
}

func newRig(t *testing.T) *rig {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay socket: %v", err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr).AddrPort()

	derpAddr, derpTLS := startTestDERP(t)

	ctl, err := control.Open(control.Config{
		DBPath:          filepath.Join(t.TempDir(), "dotlink.db"),
		AdminToken:      testAdmin,
		PublicURL:       "http://127.0.0.1:1",
		Relays:          []proto.Relay{{ID: "relay-1", UDP: addr.String(), DERP: derpAddr}},
		LongPollTimeout: 300 * time.Millisecond,
		Logger:          quietLogger(),
	})
	if err != nil {
		t.Fatalf("control plane: %v", err)
	}
	// The Relay must check HELLOs against the secret the Control Plane hands
	// out in the map, so it can only start once that secret exists.
	srv := &relay.Server{Secret: []byte(ctl.RelaySecret), Logger: quietLogger()}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { pc.Close() })

	ts := httptest.NewServer(ctl)
	t.Cleanup(func() { ts.Close(); ctl.Close() })
	return &rig{server: ts, relay: pc.(*net.UDPConn), addr: addr, secret: ctl.RelaySecret, derpAddr: derpAddr, derpTLS: derpTLS}
}

// join enrolls a Node against the rig and returns its saved state plus a home
// directory for the status snapshot.
func (r *rig) join(t *testing.T, hostname string) (State, string) {
	t.Helper()
	inv, err := control.NewAdmin(r.server.URL, testAdmin).CreateInvite(context.Background())
	if err != nil {
		t.Fatalf("create invite for %s: %v", hostname, err)
	}
	st, err := Enroll(context.Background(), EnrollLink{Server: r.server.URL, Invite: inv.Token}, hostname, "darwin")
	if err != nil {
		t.Fatalf("enroll %s: %v", hostname, err)
	}
	return st, t.TempDir()
}

// testDaemon builds a Daemon with a fake TUN and no root-only steps.
func testDaemon(st State, home string, opts ...func(*Daemon)) (*Daemon, *tuntest.ChannelTUN) {
	ch := tuntest.NewChannelTUN()
	d := &Daemon{
		State:         st,
		Home:          home,
		UDPListen:     "127.0.0.1:0",
		HelloInterval: 200 * time.Millisecond,
		MakeTUN:       func(int) (tun.Device, error) { return ch.TUN(), nil },
		Configure:     func(context.Context, netcfg.Config) error { return nil },
		// A test must never touch the host's routing table; tests that care
		// about route sync replace this with a recorder.
		SyncRoutes: func(context.Context, string, []netip.Prefix, []netip.Prefix) error { return nil },
	}
	for _, opt := range opts {
		opt(d)
	}
	return d, ch
}

// runDaemon starts d and returns the error channel plus a stop that waits for
// Run to finish, defers included.
func runDaemon(t *testing.T, d *Daemon) (chan error, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	// done, not errc, is what cleanup waits on: a test is free to read errc,
	// and a cleanup that waited on the same value would deadlock behind it.
	done := make(chan struct{})
	go func() {
		errc <- d.Run(ctx)
		close(done)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			<-done
		})
	}
	return errc, stop
}

// start runs a Daemon with a fake TUN and no root-only steps.
func start(t *testing.T, st State, home string, opts ...func(*Daemon)) (chan error, *tuntest.ChannelTUN) {
	t.Helper()
	d, ch := testDaemon(st, home, opts...)
	errc, stop := runDaemon(t, d)
	t.Cleanup(stop)
	return errc, ch
}

// startStoppable is start with an explicit stop, for tests that need a Node to
// leave the Network (and withdraw its routes) before the test ends.
func startStoppable(t *testing.T, st State, home string, opts ...func(*Daemon)) (func(), *tuntest.ChannelTUN) {
	t.Helper()
	d, ch := testDaemon(st, home, opts...)
	_, stop := runDaemon(t, d)
	t.Cleanup(stop)
	return stop, ch
}

func TestDaemonCarriesAPingBetweenTwoAgents(t *testing.T) {
	r := newRig(t)
	mini, miniHome := r.join(t, "mac-mini")
	book, bookHome := r.join(t, "macbook")

	_, miniCh := start(t, mini, miniHome)
	_, bookCh := start(t, book, bookHome)

	download := tuntest.Ping(netip.MustParseAddr(book.IPv4), netip.MustParseAddr(mini.IPv4))
	if got := deliver(t, miniCh, bookCh, download, 10*time.Second); string(got) != string(download) {
		t.Fatalf("macbook got %d bytes, want the %d sent", len(got), len(download))
	}

	rt, err := LoadRuntimeIn(bookHome)
	if err != nil {
		t.Fatalf("status snapshot: %v", err)
	}
	if len(rt.Peers) != 1 || rt.Peers[0].Hostname != "mac-mini" {
		t.Fatalf("peers = %+v, want mac-mini", rt.Peers)
	}
	// The path may already be Direct by now: punching starts on the first
	// packet. What matters here is that the snapshot names the peer at all.
	if rt.Peers[0].Path == "" {
		t.Errorf("path = %q, want a state", rt.Peers[0].Path)
	}
}

func TestDaemonPublishesItsLanCandidate(t *testing.T) {
	r := newRig(t)
	mini, miniHome := r.join(t, "mac-mini")
	book, bookHome := r.join(t, "macbook")
	start(t, mini, miniHome)
	start(t, book, bookHome)

	// The candidate lands in the Map, which is how #3 will find peers to punch.
	// It is published asynchronously, so poll instead of racing it.
	deadline := time.Now().Add(3 * time.Second)
	for {
		pm, err := book.Control().Map(context.Background(), -1)
		if err != nil || pm == nil {
			t.Fatalf("map: %v", err)
		}
		for _, peer := range pm.Peers {
			if peer.Hostname != "mac-mini" {
				continue
			}
			for _, c := range peer.Candidates {
				if c.Kind == "lan" {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("mac-mini published no lan candidate: %+v", pm.Peers)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDaemonSurvivesTheRelayVanishing(t *testing.T) {
	r := newRig(t)
	mini, miniHome := r.join(t, "mac-mini")
	book, bookHome := r.join(t, "macbook")

	errc, miniCh := start(t, mini, miniHome)
	_, bookCh := start(t, book, bookHome)
	deliver(t, miniCh, bookCh, tuntest.Ping(netip.MustParseAddr(book.IPv4), netip.MustParseAddr(mini.IPv4)), 10*time.Second)

	r.relay.Close()
	time.Sleep(600 * time.Millisecond)

	select {
	case err := <-errc:
		t.Fatalf("the tunnel died with the Relay: %v", err)
	default:
	}
}

func TestRelayRestartRestoresTraffic(t *testing.T) {
	r := newRig(t)
	mini, miniHome := r.join(t, "mac-mini")
	book, bookHome := r.join(t, "macbook")

	_, miniCh := start(t, mini, miniHome)
	_, bookCh := start(t, book, bookHome)
	deliver(t, miniCh, bookCh, tuntest.Ping(netip.MustParseAddr(book.IPv4), netip.MustParseAddr(mini.IPv4)), 10*time.Second)

	addr := r.relay.LocalAddr().String()
	r.relay.Close()
	time.Sleep(300 * time.Millisecond)

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Skipf("could not rebind the Relay port %s: %v", addr, err)
	}
	srv := &relay.Server{Secret: []byte(r.secret), Logger: quietLogger()}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { pc.Close() })

	// No restart of the Agents: their HELLOs rebuild the Relay's table.
	deliver(t, miniCh, bookCh, tuntest.Ping(netip.MustParseAddr(book.IPv4), netip.MustParseAddr(mini.IPv4)), 15*time.Second)
}

func TestTwoAgentsOnOneLanGoDirectAndSurviveTheRelay(t *testing.T) {
	r := newRig(t)
	mini, miniHome := r.join(t, "mac-mini")
	book, bookHome := r.join(t, "macbook")

	_, miniCh := start(t, mini, miniHome)
	_, bookCh := start(t, book, bookHome)
	deliver(t, miniCh, bookCh, tuntest.Ping(netip.MustParseAddr(book.IPv4), netip.MustParseAddr(mini.IPv4)), 10*time.Second)

	// Both agents advertise 127.0.0.1 as a lan candidate here, which is the
	// same shape as two machines on one wifi: the probe is answered directly.
	deadline := time.Now().Add(15 * time.Second)
	for {
		rt, err := LoadRuntimeIn(bookHome)
		if err == nil && len(rt.Peers) == 1 && rt.Peers[0].Path == "Direct" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("path never became Direct: %+v", rt.Peers)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The proof that the path is real and not a status field: kill the Relay
	// and keep talking.
	r.relay.Close()
	time.Sleep(200 * time.Millisecond)
	deliver(t, miniCh, bookCh, tuntest.Ping(netip.MustParseAddr(book.IPv4), netip.MustParseAddr(mini.IPv4)), 10*time.Second)
}

// deliver pushes packet into A's TUN until B receives something, and returns
// what B got. WireGuard needs a handshake before the first packet lands, so a
// single push can be swallowed.
func deliver(t *testing.T, a, b *tuntest.ChannelTUN, packet []byte, within time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		select {
		case a.Outbound <- packet:
		default:
			// The send queue is full; the device is busy, try again.
		}
		select {
		case got := <-b.Inbound:
			return got
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("no packet arrived within %s", within)
	return nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// startTestDERP brings up a DERP server with a throwaway certificate. It is
// the same code path as `dotlink-server relay -derp`, minus the flags.
func startTestDERP(t *testing.T) (addr string, clientTLS *tls.Config) {
	t.Helper()
	cert, pool := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("derp listener: %v", err)
	}
	srv := derp.NewServer([32]byte{9, 9, 9}, quietLogger())
	go func() { _ = srv.ServeTLS(ln, &tls.Config{Certificates: []tls.Certificate{cert}}) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), &tls.Config{RootCAs: pool}
}

// selfSigned mints a certificate for 127.0.0.1 and the pool that trusts it.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dotlink-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// TestAgentsFallBackToDERPWhenUDPIsBlocked is the acceptance criterion for
// #4: a network that stops carrying UDP must not stop the tunnel.
func TestAgentsFallBackToDERPWhenUDPIsBlocked(t *testing.T) {
	r := newRig(t)
	mini, miniHome := r.join(t, "mac-mini")
	book, bookHome := r.join(t, "macbook")

	// Relay-only keeps the punch out of the picture: on one machine a punch
	// would succeed over loopback and the packets would never touch a Relay.
	opts := func(d *Daemon) {
		d.NoPunch = true
		d.DERPAddr = r.derpAddr
		d.DERPTLS = r.derpTLS
		d.LinkFailAfter = 300 * time.Millisecond
		// The status snapshot is only rewritten on a heartbeat; a short
		// interval keeps the test from waiting 20 seconds for the truth.
		d.HeartbeatInterval = 300 * time.Millisecond
	}
	_, miniCh := start(t, mini, miniHome, opts)
	_, bookCh := start(t, book, bookHome, opts)

	ping := tuntest.Ping(netip.MustParseAddr(book.IPv4), netip.MustParseAddr(mini.IPv4))
	deliver(t, miniCh, bookCh, ping, 5*time.Second)

	// The UDP Relay disappears. HELLOs stop being answered, which is what a
	// blocked port looks like from the Agent's side.
	if err := r.relay.Close(); err != nil {
		t.Fatalf("close relay: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rt, err := LoadRuntimeIn(bookHome)
		if err == nil && rt.RelayMode == "derp" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	rt, err := LoadRuntimeIn(bookHome)
	if err != nil {
		t.Fatalf("runtime: %v", err)
	}
	if rt.RelayMode != "derp" {
		t.Fatalf("relay mode = %q after the udp relay vanished", rt.RelayMode)
	}

	// Same tunnel, different transport: the ping must still come back.
	again := tuntest.Ping(netip.MustParseAddr(book.IPv4), netip.MustParseAddr(mini.IPv4))
	deliver(t, miniCh, bookCh, again, 10*time.Second)
}

// closeRecorder is a TUN that remembers whether the daemon closed it. The
// disconnect promise is "no utun left behind", and that is exactly this bit.
type closeRecorder struct {
	tun.Device
	closed atomic.Bool
}

func (r *closeRecorder) Close() error {
	r.closed.Store(true)
	return r.Device.Close()
}

func TestDisconnectTakesTheTUNWithIt(t *testing.T) {
	r := newRig(t)
	st, home := r.join(t, "mac-mini")

	var rec *closeRecorder
	sup := &Supervisor{
		Logger: quietLogger(),
		Run: func(ctx context.Context) error {
			return (&Daemon{
				State: st, Home: home,
				UDPListen:     "127.0.0.1:0",
				HelloInterval: 200 * time.Millisecond,
				MakeTUN: func(int) (tun.Device, error) {
					rec = &closeRecorder{Device: tuntest.NewChannelTUN().TUN()}
					return rec, nil
				},
				Configure: func(context.Context, netcfg.Config) error { return nil },
				Logger:    quietLogger(),
			}).Run(ctx)
		},
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := LoadRuntimeIn(home); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	sup.Stop()
	if rec == nil {
		t.Fatal("the daemon never created a TUN")
	}
	if !rec.closed.Load() {
		t.Fatal("disconnect left the TUN open")
	}
	if _, err := LoadRuntimeIn(home); err == nil {
		t.Fatal("disconnect left a stale runtime snapshot behind")
	}
}

// TestDaemonAdvertisesSubnetRoutes is the Gateway half of a Subnet Router:
// the flag has to reach the Control Plane, and the peers have to see it as a
// route rather than as a Node with a confusing address.
func TestDaemonAdvertisesSubnetRoutes(t *testing.T) {
	r := newRig(t)
	gateway, gatewayHome := r.join(t, "gateway")
	book, bookHome := r.join(t, "macbook")

	// The daemon calls this from its own goroutine, so the config crosses the
	// boundary on a channel: a shared slice here is a data race, not a test.
	configs := make(chan netshare.Config, 1)
	_, _ = start(t, gateway, gatewayHome, func(d *Daemon) {
		d.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("192.168.1.9/24")}
		d.EnableNetshare = func(_ context.Context, cfg netshare.Config) (func(), error) {
			configs <- cfg
			return func() {}, nil
		}
	})
	start(t, book, bookHome)

	var cfg netshare.Config
	select {
	case cfg = <-configs:
	case <-time.After(10 * time.Second):
		t.Fatal("the gateway never reached netshare")
	}
	// The route arrived masked, and the tunnel name was handed to the NAT
	// setup so it can refuse a route that points back into the tunnel.
	if len(cfg.Routes) != 1 || cfg.Routes[0].String() != "192.168.1.0/24" {
		t.Fatalf("netshare got routes %v, want [192.168.1.0/24]", cfg.Routes)
	}
	if cfg.TUN == "" {
		t.Fatal("netshare was not told the TUN name")
	}

	// The advertisement travels over HTTP, so wait rather than assume. The
	// peer must see the masked route; without it the packet would leave
	// through the default gateway and never reach the tunnel.
	deadline := time.Now().Add(10 * time.Second)
	for {
		pm, err := book.Control().Map(context.Background(), -1)
		if err != nil || pm == nil {
			t.Fatalf("map from macbook: %v", err)
		}
		found := false
		for _, p := range pm.Peers {
			if p.Hostname == "gateway" && len(p.SubnetRoutes) == 1 && p.SubnetRoutes[0] == "192.168.1.0/24" {
				found = true
			}
		}
		if found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("macbook never saw the route: %+v", pm.Peers)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// gatewayRoutes reads the routes a peer sees for the named Node.
func gatewayRoutes(t *testing.T, ctl *Control, hostname string) []string {
	t.Helper()
	pm, err := ctl.Map(context.Background(), -1)
	if err != nil || pm == nil {
		t.Fatalf("map: %v", err)
	}
	for _, p := range pm.Peers {
		if p.Hostname == hostname {
			return p.SubnetRoutes
		}
	}
	return nil
}

func waitForPeerRoutes(t *testing.T, ctl *Control, hostname string, want []string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := gatewayRoutes(t, ctl, hostname)
		if strings.Join(got, ",") == strings.Join(want, ",") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s routes = %v, want %v", hostname, got, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestDaemonWithoutTheFlagWithdrawsAStaleClaim restarts an Agent that used to
// be a Gateway without --advertise-routes. The old claim must not survive: it
// would keep sending every peer's LAN traffic into a tunnel with no NAT behind
// it.
func TestDaemonWithoutTheFlagWithdrawsAStaleClaim(t *testing.T) {
	r := newRig(t)
	gateway, gatewayHome := r.join(t, "gateway")
	book, bookHome := r.join(t, "macbook")
	if err := gateway.Control().SetRoutes(context.Background(), []string{"192.168.1.0/24"}); err != nil {
		t.Fatalf("stale advertisement: %v", err)
	}
	start(t, book, bookHome)
	waitForPeerRoutes(t, book.Control(), "gateway", []string{"192.168.1.0/24"})

	start(t, gateway, gatewayHome) // no AdvertiseRoutes: the flag was dropped
	waitForPeerRoutes(t, book.Control(), "gateway", nil)
}

// commandRecorder is a netcfg.Runner that remembers what the daemon asked for,
// so a test can assert the production sync path without editing the host's
// routing table.
type commandRecorder struct {
	cmds []string
}

func (r *commandRecorder) Run(_ context.Context, name string, args ...string) error {
	r.cmds = append(r.cmds, strings.Join(append([]string{name}, args...), " "))
	return nil
}

func (r *commandRecorder) Output(_ context.Context, name string, args ...string) (string, error) {
	r.cmds = append(r.cmds, strings.Join(append([]string{name}, args...), " "))
	return "", nil
}

// TestDaemonSyncsRoutesThroughTheKernel exercises the branch production takes:
// no injected SyncRoutes, a real netcfg.AddRoute/DeleteRoute with a Runner that
// records instead of running route(8).
func TestDaemonSyncsRoutesThroughTheKernel(t *testing.T) {
	rec := &commandRecorder{}
	d := &Daemon{Runner: rec}

	if err := d.syncRoutes(context.Background(), "utun5", prefixes("192.168.1.9/24"), prefixes("10.0.0.0/8")); err != nil {
		t.Fatalf("syncRoutes: %v", err)
	}
	want := []string{
		"route -n add -net 192.168.1.0/24 -interface utun5",
		"route -n delete -net 10.0.0.0/8 -interface utun5",
	}
	if strings.Join(rec.cmds, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(rec.cmds, "\n"), strings.Join(want, "\n"))
	}
}

func TestWaitForRetryCancelAndTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitForRetry(ctx, time.Hour) {
		t.Fatal("waitForRetry returned true for a cancelled context")
	}
	if !waitForRetry(context.Background(), time.Millisecond) {
		t.Fatal("waitForRetry returned false after the timeout elapsed")
	}
}

func TestDaemonRefusesToAdvertiseTheOverlay(t *testing.T) {
	r := newRig(t)
	node, home := r.join(t, "gateway")

	errc, _ := start(t, node, home, func(d *Daemon) {
		d.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}
		d.EnableNetshare = func(context.Context, netshare.Config) (func(), error) { return func() {}, nil }
	})
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "overlaps the Overlay range") {
			t.Fatalf("err = %v, want an overlay overlap", err)
		}
		if !isPermanent(err) {
			t.Fatalf("a bad --advertise-routes flag must not be retried forever: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon accepted a route inside the Overlay range")
	}
}

// TestDaemonRefusesAConflictingAdvertisement proves a 409 from the Control
// Plane stops the Agent instead of flapping: netshare ran, the advertisement
// was rejected, and the session returned a permanent error.
func TestDaemonRefusesAConflictingAdvertisement(t *testing.T) {
	r := newRig(t)
	gateway, gatewayHome := r.join(t, "gateway")
	holder, _ := r.join(t, "holder")
	if err := holder.Control().SetRoutes(context.Background(), []string{"192.168.1.0/24"}); err != nil {
		t.Fatalf("holder claim: %v", err)
	}

	stopped := make(chan struct{}, 1)
	errc, _ := start(t, gateway, gatewayHome, func(d *Daemon) {
		d.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
		d.EnableNetshare = func(context.Context, netshare.Config) (func(), error) {
			return func() { stopped <- struct{}{} }, nil
		}
	})

	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "advertise routes") || !strings.Contains(err.Error(), "409") {
			t.Fatalf("err = %v, want a 409 advertising error", err)
		}
		if !isPermanent(err) {
			t.Fatalf("a rejected advertisement must not be retried every two seconds: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon kept running with a refused advertisement")
	}

	// The privileged setup ran before the advertisement (that ordering keeps a
	// broken Gateway from black-holing the LAN), so its cleanup must have run.
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("netshare cleanup did not run after the rejected advertisement")
	}
}

// TestDaemonWithdrawsItsOldClaimWhenTheNewOneIsRejected: a rejected update
// must not leave the previous LAN pointing at an Agent that is going down.
func TestDaemonWithdrawsItsOldClaimWhenTheNewOneIsRejected(t *testing.T) {
	r := newRig(t)
	gateway, gatewayHome := r.join(t, "gateway")
	holder, _ := r.join(t, "holder")

	if err := gateway.Control().SetRoutes(context.Background(), []string{"10.5.0.0/24"}); err != nil {
		t.Fatalf("old claim: %v", err)
	}
	// The claim must be visible to a real peer before the restart: reading it
	// back from the gateway's own map proves nothing, because a node's map
	// leaves itself out and would be nil whether or not the claim exists.
	waitForPeerRoutes(t, holder.Control(), "gateway", []string{"10.5.0.0/24"})
	if err := holder.Control().SetRoutes(context.Background(), []string{"192.168.1.0/24"}); err != nil {
		t.Fatalf("holder claim: %v", err)
	}

	errc, _ := start(t, gateway, gatewayHome, func(d *Daemon) {
		d.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
		d.EnableNetshare = func(context.Context, netshare.Config) (func(), error) { return func() {}, nil }
	})
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "advertise routes") {
			t.Fatalf("err = %v, want an advertising error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon kept running with a refused advertisement")
	}

	// The old claim must be gone as a peer sees it, not as the gateway's own
	// map reports it.
	waitForPeerRoutes(t, holder.Control(), "gateway", nil)
}

// routeSync is one call the daemon made to reconcile peer routes.
type routeSync struct {
	add, remove []netip.Prefix
}

func prefixes(ps ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

func hasRoute(ps []netip.Prefix, want string) bool {
	for _, pr := range ps {
		if pr.String() == want {
			return true
		}
	}
	return false
}

// waitForRoutes returns the first sync call matching match.
func waitForRoutes(t *testing.T, calls <-chan routeSync, match func(routeSync) bool) routeSync {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case call := <-calls:
			if match(call) {
				return call
			}
		case <-deadline:
			t.Fatal("the peer never synced the expected route")
		}
	}
}

func TestRouteDelta(t *testing.T) {
	cases := []struct {
		name        string
		installed   []netip.Prefix
		desired     []netip.Prefix
		add, remove []netip.Prefix
	}{
		{
			name:      "nothing changes",
			installed: prefixes("192.168.1.0/24"),
			desired:   prefixes("192.168.1.0/24"),
		},
		{
			name:      "a gateway appears",
			installed: nil,
			desired:   prefixes("192.168.1.0/24", "10.0.0.0/8"),
			add:       prefixes("10.0.0.0/8", "192.168.1.0/24"),
		},
		{
			name:      "a gateway leaves",
			installed: prefixes("192.168.1.0/24", "10.0.0.0/8"),
			desired:   prefixes("10.0.0.0/8"),
			remove:    prefixes("192.168.1.0/24"),
		},
		{
			name:      "unmasked input is the same LAN",
			installed: prefixes("192.168.1.0/24"),
			desired:   prefixes("192.168.1.9/24"),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			add, remove := routeDelta(c.installed, c.desired)
			if strings.Join(routeStrings(add), ",") != strings.Join(routeStrings(c.add), ",") {
				t.Fatalf("add = %v, want %v", add, c.add)
			}
			if strings.Join(routeStrings(remove), ",") != strings.Join(routeStrings(c.remove), ",") {
				t.Fatalf("remove = %v, want %v", remove, c.remove)
			}
		})
	}
}

// TestPeerInstallsAGatewaysRouteWhenItAppears starts the peer before the
// Gateway: the peer's initial Configure sees no LAN at all, so the route has to
// arrive through the map loop. A Gateway that leaves must take the route with
// it — a stale route black-holes that LAN until the peer restarts.
func TestPeerInstallsAGatewaysRouteWhenItAppears(t *testing.T) {
	r := newRig(t)
	gateway, gatewayHome := r.join(t, "gateway")
	book, bookHome := r.join(t, "macbook")

	syncs := make(chan routeSync, 16)
	configured := make(chan struct{}, 1)
	_, _ = start(t, book, bookHome, func(d *Daemon) {
		d.Configure = func(context.Context, netcfg.Config) error {
			configured <- struct{}{}
			return nil
		}
		d.SyncRoutes = func(_ context.Context, iface string, add, remove []netip.Prefix) error {
			if iface == "" {
				t.Error("route sync was not told the interface")
			}
			syncs <- routeSync{add: add, remove: remove}
			return nil
		}
	})

	// Wait for the peer's own Configure: if the Gateway advertised first, the
	// route would arrive with the initial map and this test would never see
	// the dynamic path it exists to cover.
	select {
	case <-configured:
	case <-time.After(10 * time.Second):
		t.Fatal("the peer never configured its TUN")
	}

	stopGateway, _ := startStoppable(t, gateway, gatewayHome, func(d *Daemon) {
		d.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("10.9.0.9/24")}
		d.EnableNetshare = func(context.Context, netshare.Config) (func(), error) { return func() {}, nil }
	})

	call := waitForRoutes(t, syncs, func(c routeSync) bool { return hasRoute(c.add, "10.9.0.0/24") })
	if hasRoute(call.remove, "10.9.0.0/24") {
		t.Fatalf("the first sync both adds and removes the route: %+v", call)
	}

	stopGateway()
	waitForRoutes(t, syncs, func(c routeSync) bool { return hasRoute(c.remove, "10.9.0.0/24") })
}

func TestRejectedStatusSeparatesBusyFromWrong(t *testing.T) {
	cases := map[int]bool{
		400: true,
		401: true,
		403: true,
		404: true,
		405: true,
		409: true,
		422: true,
		408: false,
		429: false,
		500: false,
		503: false,
	}
	for code, want := range cases {
		if got := rejectedStatus(code); got != want {
			t.Errorf("rejectedStatus(%d) = %v, want %v", code, got, want)
		}
	}
}
