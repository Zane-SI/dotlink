package relay

import (
	"bytes"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

const (
	secretA = "relay-secret-for-tests"
)

var (
	alice = key(0xa1)
	bob   = key(0xb2)
)

type relayHarness struct {
	t    *testing.T
	srv  *Server
	pc   net.PacketConn
	addr netip.AddrPort
}

func startRelay(t *testing.T, secret string) *relayHarness {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return serveOn(t, pc, secret)
}

func serveOn(t *testing.T, pc net.PacketConn, secret string) *relayHarness {
	t.Helper()
	srv := &Server{Secret: []byte(secret), Skew: time.Minute, TTL: time.Minute}
	ap, ok := addrPort(pc.LocalAddr())
	if !ok {
		t.Fatal("bad local addr")
	}
	go func() { _ = srv.Serve(pc) }()
	h := &relayHarness{t: t, srv: srv, pc: pc, addr: ap}
	t.Cleanup(func() { pc.Close() })
	return h
}

func (h *relayHarness) client(pub [32]byte, secret string) *Client {
	h.t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatalf("listen client: %v", err)
	}
	c, err := NewClient(pc, Config{
		Relay:         h.addr,
		Pub:           pub,
		Secret:        []byte(secret),
		HelloInterval: 40 * time.Millisecond,
	})
	if err != nil {
		h.t.Fatalf("NewClient: %v", err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func recv(t *testing.T, c *Client, timeout time.Duration) Packet {
	t.Helper()
	select {
	case p := <-c.Packets():
		return p
	case <-time.After(timeout):
		t.Fatalf("no packet within %v", timeout)
		return Packet{}
	}
}

func TestServerForwardsBetweenTwoClients(t *testing.T) {
	h := startRelay(t, secretA)
	a, b := h.client(alice, secretA), h.client(bob, secretA)

	waitFor(t, "both registered", 2*time.Second, func() bool {
		return a.Registered() && b.Registered() && h.srv.Registered() == 2
	})

	if err := a.SendTo(bob, []byte("ping")); err != nil {
		t.Fatalf("SendTo: %v", err)
	}
	p := recv(t, b, 2*time.Second)
	if !p.Relay {
		t.Error("packet not marked as relayed")
	}
	if p.Key != alice {
		t.Errorf("source key = %x, want alice", p.Key)
	}
	if string(p.Payload) != "ping" {
		t.Errorf("payload = %q", p.Payload)
	}

	// And the other way, so we know the table is keyed on both sides.
	if err := b.SendTo(alice, []byte("pong")); err != nil {
		t.Fatalf("SendTo: %v", err)
	}
	if p := recv(t, a, 2*time.Second); string(p.Payload) != "pong" || p.Key != bob {
		t.Fatalf("reverse path got %q from %x", p.Payload, p.Key)
	}
}

func TestServerDropsDataFromUnregisteredSender(t *testing.T) {
	h := startRelay(t, secretA)
	b := h.client(bob, secretA)
	waitFor(t, "bob registered", 2*time.Second, b.Registered)

	// A socket that never said HELLO, claiming to be alice.
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.WriteTo(Data(nil, bob, []byte("spoofed")), net.UDPAddrFromAddrPort(h.addr)); err != nil {
		t.Fatal(err)
	}

	select {
	case p := <-b.Packets():
		t.Fatalf("unregistered sender got through: %q", p.Payload)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestServerRejectsHelloWithWrongSecret(t *testing.T) {
	h := startRelay(t, secretA)
	bad := h.client(alice, "not-the-relay-secret")
	good := h.client(bob, secretA)

	waitFor(t, "bob registered", 2*time.Second, good.Registered)
	time.Sleep(150 * time.Millisecond)
	if bad.Registered() {
		t.Fatal("client with the wrong secret was registered")
	}

	// Even though it thinks it is registered, nothing may reach bob.
	_ = bad.SendTo(bob, []byte("let me in"))
	select {
	case p := <-good.Packets():
		t.Fatalf("unauthenticated traffic got through: %q", p.Payload)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestServerExpiresSilentRegistration(t *testing.T) {
	var now atomic.Int64
	base := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	now.Store(base.UnixNano())

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Secret: []byte(secretA),
		Skew:   time.Minute,
		TTL:    10 * time.Second,
		Now:    func() time.Time { return time.Unix(0, now.Load()) },
	}
	ap, _ := addrPort(pc.LocalAddr())
	go func() { _ = srv.Serve(pc) }()
	defer pc.Close()

	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.WriteTo(Hello(nil, alice, base, []byte(secretA)), net.UDPAddrFromAddrPort(ap)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "registered", time.Second, func() bool { return srv.Registered() == 1 })

	now.Store(base.Add(11 * time.Second).UnixNano())
	if n := srv.Registered(); n != 0 {
		t.Fatalf("still %d registrations after TTL", n)
	}
}

// The acceptance criterion for #2: a Relay restart must heal itself without
// anyone touching the Agent.
func TestClientReregistersAfterRelayRestart(t *testing.T) {
	h := startRelay(t, secretA)
	a, b := h.client(alice, secretA), h.client(bob, secretA)
	waitFor(t, "both registered", 2*time.Second, func() bool {
		return a.Registered() && b.Registered()
	})
	if err := a.SendTo(bob, []byte("before")); err != nil {
		t.Fatal(err)
	}
	if p := recv(t, b, time.Second); string(p.Payload) != "before" {
		t.Fatalf("payload = %q", p.Payload)
	}

	// Kill the Relay and bring it back on the same port with an empty table.
	port := h.addr.Port()
	h.pc.Close()
	time.Sleep(50 * time.Millisecond)
	pc2, err := net.ListenPacket("udp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
	if err != nil {
		t.Fatalf("relisten: %v", err)
	}
	h2 := serveOn(t, pc2, secretA)

	waitFor(t, "clients re-registered with the new Relay", 3*time.Second, func() bool {
		return h2.srv.Registered() == 2
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := a.SendTo(bob, []byte("after")); err != nil {
			t.Fatal(err)
		}
		select {
		case p := <-b.Packets():
			if bytes.Equal(p.Payload, []byte("after")) && p.Key == alice {
				return
			}
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("traffic did not resume after the Relay restart")
		}
	}
}

func TestClientDeliversRawPacketsAsDirect(t *testing.T) {
	h := startRelay(t, secretA)
	a := h.client(alice, secretA)
	waitFor(t, "registered", 2*time.Second, a.Registered)

	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.WriteTo([]byte("raw wireguard"), net.UDPAddrFromAddrPort(a.LocalAddr())); err != nil {
		t.Fatal(err)
	}
	p := recv(t, a, time.Second)
	if p.Relay {
		t.Fatal("raw packet marked as relayed")
	}
	if string(p.Payload) != "raw wireguard" {
		t.Fatalf("payload = %q", p.Payload)
	}
	if !p.Addr.IsValid() {
		t.Fatal("raw packet has no source address")
	}
}
