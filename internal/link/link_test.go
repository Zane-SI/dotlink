package link

import (
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Zane-SI/dotlink/internal/derp"
	"github.com/Zane-SI/dotlink/internal/relay"
)

type fakeUDP struct {
	mu      sync.Mutex
	up      bool
	packets chan relay.Packet
	sentKey []byte
	sentDir []byte
}

func newFakeUDP() *fakeUDP {
	return &fakeUDP{packets: make(chan relay.Packet, 8)}
}

func (f *fakeUDP) setRegistered(v bool) { f.mu.Lock(); f.up = v; f.mu.Unlock() }
func (f *fakeUDP) Registered() bool     { f.mu.Lock(); defer f.mu.Unlock(); return f.up }
func (f *fakeUDP) Close() error         { return nil }
func (f *fakeUDP) LocalAddr() netip.AddrPort {
	return netip.MustParseAddrPort("10.0.0.1:41641")
}
func (f *fakeUDP) Packets() <-chan relay.Packet { return f.packets }
func (f *fakeUDP) SendTo(key [32]byte, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sentKey = payload
	return nil
}
func (f *fakeUDP) SendToAddr(addr netip.AddrPort, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sentDir = payload
	return nil
}

type fakeDERP struct {
	mu      sync.Mutex
	up      bool
	packets chan derp.Packet
	sent    []byte
}

func newFakeDERP() *fakeDERP { return &fakeDERP{packets: make(chan derp.Packet, 8)} }

func (f *fakeDERP) setRegistered(v bool)        { f.mu.Lock(); f.up = v; f.mu.Unlock() }
func (f *fakeDERP) Registered() bool            { f.mu.Lock(); defer f.mu.Unlock(); return f.up }
func (f *fakeDERP) Close() error                { return nil }
func (f *fakeDERP) Packets() <-chan derp.Packet { return f.packets }
func (f *fakeDERP) SendTo(key [32]byte, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = payload
	return nil
}

func testLink(t *testing.T) (*Link, *fakeUDP, *fakeDERP) {
	t.Helper()
	udp, d := newFakeUDP(), newFakeDERP()
	l := New(udp, d, slog.New(slog.DiscardHandler))
	l.FailAfter = 50 * time.Millisecond
	t.Cleanup(func() { _ = l.Close() })
	return l, udp, d
}

func TestRelayedTrafficPrefersUDP(t *testing.T) {
	l, udp, d := testLink(t)
	udp.setRegistered(true)
	d.setRegistered(true)
	l.Tick()
	if err := l.SendTo([32]byte{1}, []byte("over udp")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if string(udp.sentKey) != "over udp" {
		t.Fatalf("udp saw %q, derp saw %q", udp.sentKey, d.sent)
	}
	if l.Mode() != ModeUDP {
		t.Fatalf("mode = %s", l.Mode())
	}
}

func TestFallsBackToDERPWhenUDPStaysDown(t *testing.T) {
	l, udp, d := testLink(t)
	udp.setRegistered(false)
	d.setRegistered(true)

	l.Tick() // starts the clock, does not switch yet
	if l.Mode() != ModeUDP {
		t.Fatalf("switched before FailAfter: %s", l.Mode())
	}
	time.Sleep(80 * time.Millisecond)
	l.Tick()
	if l.Mode() != ModeDERP {
		t.Fatalf("mode = %s, want derp", l.Mode())
	}
	if err := l.SendTo([32]byte{2}, []byte("over tls")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if string(d.sent) != "over tls" {
		t.Fatalf("derp saw %q", d.sent)
	}
}

func TestStaysOnUDPWhenDERPIsAlsoDown(t *testing.T) {
	l, udp, d := testLink(t)
	udp.setRegistered(false)
	d.setRegistered(false)
	l.Tick()
	time.Sleep(80 * time.Millisecond)
	l.Tick()
	if l.Mode() != ModeUDP {
		t.Fatalf("mode = %s; switching to a dead transport helps nobody", l.Mode())
	}
}

func TestReturnsToUDPAsSoonAsItRecovers(t *testing.T) {
	l, udp, d := testLink(t)
	udp.setRegistered(false)
	d.setRegistered(true)
	l.Tick()
	time.Sleep(80 * time.Millisecond)
	l.Tick()
	if l.Mode() != ModeDERP {
		t.Fatalf("mode = %s", l.Mode())
	}
	udp.setRegistered(true)
	l.Tick()
	if l.Mode() != ModeUDP {
		t.Fatalf("mode = %s after recovery", l.Mode())
	}
}

func TestDirectSendsAlwaysUseTheUDPSocket(t *testing.T) {
	l, udp, d := testLink(t)
	udp.setRegistered(false)
	d.setRegistered(true)
	l.Tick()
	time.Sleep(80 * time.Millisecond)
	l.Tick()
	if l.Mode() != ModeDERP {
		t.Fatalf("mode = %s", l.Mode())
	}
	if err := l.SendToAddr(netip.MustParseAddrPort("1.2.3.4:5000"), []byte("direct")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if string(udp.sentDir) != "direct" {
		t.Fatalf("the direct datagram did not leave the udp socket")
	}
}

func TestPacketsFromBothTransportsShareOneStream(t *testing.T) {
	l, udp, d := testLink(t)
	udp.packets <- relay.Packet{Relay: true, Key: [32]byte{1}, Payload: []byte("via udp")}
	d.packets <- derp.Packet{Key: [32]byte{2}, Payload: []byte("via derp")}

	got := map[string][32]byte{}
	for i := 0; i < 2; i++ {
		select {
		case p := <-l.Packets():
			if !p.Relay {
				t.Fatalf("packet %q is not marked relayed", p.Payload)
			}
			got[string(p.Payload)] = p.Key
		case <-time.After(2 * time.Second):
			t.Fatalf("only received %v", got)
		}
	}
	if got["via udp"] != [32]byte{1} || got["via derp"] != [32]byte{2} {
		t.Fatalf("keys = %v", got)
	}
}
