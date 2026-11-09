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
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/Zane-SI/dotlink/internal/control"
	"github.com/Zane-SI/dotlink/internal/derp"
	"github.com/Zane-SI/dotlink/internal/netcfg"
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

// start runs a Daemon with a fake TUN and no root-only steps.
func start(t *testing.T, st State, home string, opts ...func(*Daemon)) (chan error, *tuntest.ChannelTUN) {
	t.Helper()
	ch := tuntest.NewChannelTUN()
	d := &Daemon{
		State:         st,
		Home:          home,
		UDPListen:     "127.0.0.1:0",
		HelloInterval: 200 * time.Millisecond,
		MakeTUN:       func(int) (tun.Device, error) { return ch.TUN(), nil },
		Configure:     func(context.Context, netcfg.Config) error { return nil },
	}
	for _, opt := range opts {
		opt(d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- d.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-errc })
	return errc, ch
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
