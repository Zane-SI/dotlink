package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/Zane-SI/dotlink/internal/relay"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

const testSecret = "relay-secret-for-tunnel-tests"

type node struct {
	name   string
	priv   [32]byte
	pub    [32]byte
	ipv4   netip.Addr
	client *relay.Client
	dev    *Device
	ch     *tuntest.ChannelTUN
	ctl    net.PacketConn
}

func keypair(t *testing.T) (priv, pub [32]byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	copy(priv[:], k.Bytes())
	copy(pub[:], k.PublicKey().Bytes())
	return priv, pub
}

func newTestTunnelNode(t *testing.T, name string, ip string, relayAddr netip.AddrPort) *node {
	t.Helper()
	priv, pub := keypair(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen %s: %v", name, err)
	}
	client, err := relay.NewClient(pc, relay.Config{
		Relay:         relayAddr,
		Pub:           pub,
		Secret:        []byte(testSecret),
		HelloInterval: 40 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("relay client %s: %v", name, err)
	}
	bind := NewBind(client)
	tuntestCh := tuntest.NewChannelTUN()
	dev, err := New(tuntestCh.TUN(), bind, DeviceConfig{
		PrivateKey: priv,
		Logger:     device.NewLogger(device.LogLevelError, name),
	})
	if err != nil {
		t.Fatalf("device %s: %v", name, err)
	}
	t.Cleanup(func() {
		dev.Close()
		pc.Close()
	})
	return &node{name: name, priv: priv, pub: pub, ipv4: netip.MustParseAddr(ip), client: client, dev: dev, ch: tuntestCh, ctl: pc}
}

// configurePeers sets each Node's view of the other, which is what the Peer
// Map does in production.
func configurePeers(t *testing.T, a, b *node) {
	t.Helper()
	for _, pair := range [][2]*node{{a, b}, {b, a}} {
		self, other := pair[0], pair[1]
		if err := self.dev.Apply([]Peer{{
			Pub:      other.pub,
			Prefixes: []netip.Prefix{netip.PrefixFrom(other.ipv4, 32)},
		}}); err != nil {
			t.Fatalf("configure %s: %v", self.name, err)
		}
	}
}

func startTestRelay(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &relay.Server{
		Secret: []byte(testSecret),
		TTL:    time.Minute,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func waitRegistered(t *testing.T, nodes ...*node) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for _, n := range nodes {
			all = all && n.client.Registered()
		}
		if all {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("nodes did not register with the relay")
}

// The end-to-end criterion for #2 without needing root: two real WireGuard
// devices, a real Relay over real UDP, and a real IPv4 packet crossing.
func TestTwoDevicesExchangePacketsThroughRelay(t *testing.T) {
	relayAddr := startTestRelay(t)
	a := newTestTunnelNode(t, "mac-mini", "100.64.0.1", relayAddr)
	b := newTestTunnelNode(t, "macbook", "100.64.0.2", relayAddr)
	configurePeers(t, a, b)
	waitRegistered(t, a, b)

	ping := tuntest.Ping(b.ipv4, a.ipv4)
	select {
	case a.ch.Outbound <- ping:
	case <-time.After(time.Second):
		t.Fatal("device a did not read from tun")
	}

	select {
	case got := <-b.ch.Inbound:
		if !bytes.Equal(got, ping) {
			t.Fatalf("delivered packet differs\n got %x\nwant %x", got, ping)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no packet arrived at the other side")
	}
}

func TestDeviceDropsPacketsBeforeRegistration(t *testing.T) {
	// A Relay that never answers: the Agent must not claim to be registered.
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := dead.LocalAddr().(*net.UDPAddr).AddrPort()
	dead.Close()

	n := newTestTunnelNode(t, "lonely", "100.64.0.9", addr)
	time.Sleep(200 * time.Millisecond)
	if n.client.Registered() {
		t.Fatal("registered with a relay that does not exist")
	}
}
