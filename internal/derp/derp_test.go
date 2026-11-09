package derp

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

func startServer(t *testing.T) (addr string, clientTLS *tls.Config) {
	t.Helper()
	serverTLS, clientTLS := testTLS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := NewServer([32]byte{1, 2, 3}, slog.New(slog.DiscardHandler))
	srv.PingInterval = 50 * time.Millisecond
	go func() { _ = srv.ServeTLS(ln, serverTLS) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), clientTLS
}

func dial(t *testing.T, addr string, tlsCfg *tls.Config, key byte) *Client {
	t.Helper()
	var k [32]byte
	k[0] = key
	c, err := Dial(context.Background(), Config{
		Addr:         addr,
		TLS:          tlsCfg,
		Key:          k,
		Logger:       slog.New(slog.DiscardHandler),
		PingInterval: 30 * time.Millisecond,
		KeepAlive:    50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func waitRegistered(t *testing.T, c *Client) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c.Registered() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the connection never registered")
}

func TestPingPongMarksTheClientRegistered(t *testing.T) {
	addr, tlsCfg := startServer(t)
	c := dial(t, addr, tlsCfg, 7)
	// A finished handshake counts as reachable; the ping confirms it and
	// keeps it true.
	waitRegistered(t, c)
	if key := c.ServerKey(); key != [32]byte{1, 2, 3} {
		t.Fatalf("server key = %x", key[:4])
	}
}

func TestPacketsTravelBetweenKeys(t *testing.T) {
	addr, tlsCfg := startServer(t)
	a, b := dial(t, addr, tlsCfg, 1), dial(t, addr, tlsCfg, 2)
	waitRegistered(t, a)
	waitRegistered(t, b)

	want := [32]byte{1}
	if err := a.SendTo([32]byte{2}, []byte("hello beacon")); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case p := <-b.Packets():
		if string(p.Payload) != "hello beacon" {
			t.Fatalf("payload = %q", p.Payload)
		}
		if p.Key != want {
			t.Fatalf("source = %v, want %v", p.Key[:2], want[:2])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the packet never arrived")
	}
}

func TestPacketForAnAbsentPeerIsDropped(t *testing.T) {
	addr, tlsCfg := startServer(t)
	a := dial(t, addr, tlsCfg, 1)
	waitRegistered(t, a)
	if err := a.SendTo([32]byte{99}, []byte("nobody home")); err != nil {
		t.Fatalf("send to an absent peer returned %v, want nil", err)
	}
	// The sender must survive: a peer being offline is normal.
	time.Sleep(100 * time.Millisecond)
	if !a.Registered() {
		t.Fatal("the sender lost its connection because a peer was absent")
	}
}

func TestReconnectingWithTheSameKeyReplacesTheOldConnection(t *testing.T) {
	addr, tlsCfg := startServer(t)
	older := dial(t, addr, tlsCfg, 5)
	waitRegistered(t, older)
	newer := dial(t, addr, tlsCfg, 5)
	waitRegistered(t, newer)

	sender := dial(t, addr, tlsCfg, 6)
	waitRegistered(t, sender)
	if err := sender.SendTo([32]byte{5}, []byte("for the newest")); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case p := <-newer.Packets():
		if string(p.Payload) != "for the newest" {
			t.Fatalf("payload = %q", p.Payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the new connection never received the packet")
	}
	if older.Registered() {
		t.Fatal("the replaced connection still believes it is registered")
	}
}

func TestPlainHTTPIsRejected(t *testing.T) {
	addr, _ := startServer(t)
	resp, err := http.Get("http://" + addr + Path)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("a plain HTTP request was upgraded")
	}
}

// TestDERPForwardsAtLineRate holds the throughput floor from #4: a self-hosted
// Relay must carry a single stream at 20 Mbit/s, or falling back to it turns a
// working tunnel into an unusable one. Loopback is far faster than any real
// link, so this catches structural mistakes (a frame copied per hop, a
// synchronous write per packet), not network luck.
func TestDERPForwardsAtLineRate(t *testing.T) {
	addr, tlsCfg := startServer(t)
	a, b := dial(t, addr, tlsCfg, 1), dial(t, addr, tlsCfg, 2)
	waitRegistered(t, a)
	waitRegistered(t, b)

	const (
		chunk = 16 << 10
		total = 8 << 20
	)
	payload := make([]byte, chunk)
	start := time.Now()

	done := make(chan int, 1)
	go func() {
		got := 0
		for got < total {
			select {
			case p := <-b.Packets():
				got += len(p.Payload)
			case <-time.After(20 * time.Second):
				done <- got
				return
			}
		}
		done <- got
	}()

	for sent := 0; sent < total; sent += chunk {
		if err := a.SendTo([32]byte{2}, payload); err != nil {
			t.Fatalf("send at %d bytes: %v", sent, err)
		}
	}
	got := <-done
	elapsed := time.Since(start)
	mbit := float64(got*8) / elapsed.Seconds() / 1e6
	t.Logf("derp carried %d bytes in %s (%.1f Mbit/s)", got, elapsed.Round(time.Millisecond), mbit)
	if got < total {
		t.Fatalf("only %d of %d bytes arrived", got, total)
	}
	if mbit < 20 {
		t.Fatalf("throughput %.1f Mbit/s is below the 20 Mbit/s floor", mbit)
	}
}
