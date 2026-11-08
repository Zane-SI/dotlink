package punch

import (
	"crypto/ecdh"
	"crypto/rand"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type keys struct {
	priv [32]byte
	pub  [32]byte
}

func newKeys(t *testing.T) keys {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var out keys
	copy(out.priv[:], k.Bytes())
	copy(out.pub[:], k.PublicKey().Bytes())
	return out
}

var (
	addrA   = netip.MustParseAddrPort("192.168.1.10:41641")
	addrB   = netip.MustParseAddrPort("192.168.1.20:41641")
	addrPub = netip.MustParseAddrPort("203.0.113.7:51820")
)

func TestPingOpensForTheNodeItWasSealedTo(t *testing.T) {
	a, b := newKeys(t), newKeys(t)
	now := time.Now()

	frame := Ping(a.priv, a.pub, b.pub, now)
	if !IsProbe(frame) {
		t.Fatal("a probe does not carry the magic")
	}
	got, err := Open(frame, b.priv, b.pub, now, time.Minute)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.Kind != KindPing || got.Sender != a.pub {
		t.Fatalf("probe = %+v, want a ping from a", got)
	}
	if !got.SentAt.Equal(now) {
		t.Errorf("sent at %s, want %s", got.SentAt, now)
	}
}

func TestOnlyTheHolderOfTheKeyCanAnswer(t *testing.T) {
	a, b, eavesdropper := newKeys(t), newKeys(t), newKeys(t)
	now := time.Now()
	frame := Pong(a.priv, a.pub, b.pub, now)

	if _, err := Open(frame, eavesdropper.priv, eavesdropper.pub, now, time.Minute); err == nil {
		t.Fatal("a third party opened a frame addressed to someone else")
	}

	tampered := append([]byte(nil), frame...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := Open(tampered, b.priv, b.pub, now, time.Minute); err == nil {
		t.Fatal("a tampered frame opened")
	}
}

func TestForgedSenderIsRejected(t *testing.T) {
	a, b, forger := newKeys(t), newKeys(t), newKeys(t)
	now := time.Now()

	// The forger writes a's public key into the clear header but seals with
	// its own key: the seal has to fail.
	frame := Pong(forger.priv, a.pub, b.pub, now)
	if _, err := Open(frame, b.priv, b.pub, now, time.Minute); err != ErrForged {
		t.Fatalf("err = %v, want ErrForged", err)
	}
}

func TestStaleProbeIsRejected(t *testing.T) {
	a, b := newKeys(t), newKeys(t)
	now := time.Now()
	frame := Ping(a.priv, a.pub, b.pub, now.Add(-5*time.Minute))

	if _, err := Open(frame, b.priv, b.pub, now, time.Minute); err != ErrStale {
		t.Fatalf("err = %v, want ErrStale", err)
	}
}

func TestNotAProbeIsReportedAsSuch(t *testing.T) {
	a, b := newKeys(t), newKeys(t)
	if _, err := Open([]byte("hello"), b.priv, b.pub, time.Now(), time.Minute); err != ErrNotAProbe {
		t.Fatalf("err = %v, want ErrNotAProbe", err)
	}
	if _, err := Open(Ping(a.priv, a.pub, b.pub, time.Now())[:40], b.priv, b.pub, time.Now(), time.Minute); err != ErrNotAProbe {
		t.Fatalf("short frame: err = %v, want ErrNotAProbe", err)
	}
}

// harness is a fake wire: the manager sends probes here, and the test decides
// whether the far side answers.
type harness struct {
	mgr   *Manager
	mu    sync.Mutex
	now   time.Time
	peer  keys
	sent  []sentProbe
	reach map[netip.AddrPort]bool
	drop  bool
}

type sentProbe struct {
	addr  netip.AddrPort
	frame []byte
}

func newHarness(t *testing.T, reachable ...netip.AddrPort) *harness {
	t.Helper()
	local, peer := newKeys(t), newKeys(t)
	h := &harness{now: time.Unix(1_700_000_000, 0), peer: peer, reach: map[netip.AddrPort]bool{}}
	for _, a := range reachable {
		h.reach[a] = true
	}
	h.mgr = New(Config{
		Private:   local.priv,
		Public:    local.pub,
		Transport: h,
		Logger:    slog.New(slog.DiscardHandler),
		Now:       func() time.Time { return h.now },
	})
	h.mgr.SetPeers([]Peer{{Key: peer.pub, Candidates: []netip.AddrPort{addrA, addrB}}})
	return h
}

func (h *harness) SendProbe(addr netip.AddrPort, frame []byte) error {
	h.mu.Lock()
	h.sent = append(h.sent, sentProbe{addr: addr, frame: frame})
	reachable := h.reach[addr] && !h.drop
	now := h.now
	h.mu.Unlock()
	if !reachable {
		return nil
	}
	// The far side answers from the address the probe came from, which is the
	// whole point: its reply teaches us our own public mapping.
	reply := Pong(h.peer.priv, h.peer.pub, h.mgr.cfg.Public, now)
	h.mgr.Handle(addr, reply)
	return nil
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func (h *harness) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sent)
}

func TestPunchGoesDirectOnAPong(t *testing.T) {
	h := newHarness(t, addrB)
	key := h.peer.pub

	if s, _ := h.mgr.State(key); s != StateIdle {
		t.Fatalf("state = %s, want Idle before any traffic", s)
	}
	h.mgr.Touch(key)

	// One round is enough: the harness answers immediately.
	for i := 0; i < 5; i++ {
		h.mgr.Tick()
		h.advance(DefaultInterval)
	}
	if s, rtt := h.mgr.State(key); s != StateDirect {
		t.Fatalf("state = %s, want Direct", s)
	} else if rtt < 0 {
		t.Fatalf("rtt = %s", rtt)
	}
	addr, ok := h.mgr.Route(key)
	if !ok || addr != addrB {
		t.Fatalf("route = %s, %v, want %s", addr, ok, addrB)
	}
}

func TestPunchGivesUpAfterFiveRounds(t *testing.T) {
	h := newHarness(t) // nothing is reachable
	key := h.peer.pub
	h.mgr.Touch(key)

	for i := 0; i < DefaultRounds+1; i++ {
		h.mgr.Tick()
		h.advance(DefaultInterval)
	}
	if s, _ := h.mgr.State(key); s != StateRelayed {
		t.Fatalf("state = %s, want Relayed", s)
	}
	if _, ok := h.mgr.Route(key); ok {
		t.Fatal("a relayed peer reported a direct route")
	}
	if got, want := h.count(), DefaultRounds*2; got != want {
		t.Fatalf("sent %d probes, want %d (two candidates × five rounds)", got, want)
	}

	// Every round is retried after the retry interval, and only then.
	before := h.count()
	h.advance(DefaultRetry - time.Second)
	h.mgr.Tick()
	if h.count() != before {
		t.Fatal("a probe went out before the retry interval elapsed")
	}
	h.advance(time.Second)
	h.mgr.Tick()
	if h.count() == before {
		t.Fatal("the retry round did not go out")
	}
}

func TestADirectPathDropsBackAfterThreeMisses(t *testing.T) {
	h := newHarness(t, addrB)
	key := h.peer.pub
	h.mgr.Touch(key)
	for i := 0; i < 3; i++ {
		h.mgr.Tick()
		h.advance(DefaultInterval)
	}
	if s, _ := h.mgr.State(key); s != StateDirect {
		t.Fatalf("state = %s, want Direct", s)
	}

	h.mu.Lock()
	h.drop = true
	h.mu.Unlock()
	for i := 0; i < DefaultMaxMisses+2; i++ {
		h.mgr.Tick()
		h.advance(DefaultKeepalive)
	}
	if s, _ := h.mgr.State(key); s != StateRelayed {
		t.Fatalf("state = %s, want Relayed after three unanswered keepalives", s)
	}
}

func TestMapRefreshKeepsAWorkingPath(t *testing.T) {
	h := newHarness(t, addrB)
	key := h.peer.pub
	h.mgr.Touch(key)
	h.mgr.Tick()
	if s, _ := h.mgr.State(key); s != StateDirect {
		t.Fatalf("state = %s, want Direct", s)
	}

	h.mgr.SetPeers([]Peer{{Key: h.peer.pub, Candidates: []netip.AddrPort{addrA, addrB}}})
	if s, _ := h.mgr.State(key); s != StateDirect {
		t.Fatalf("state = %s, want the path to survive a map refresh", s)
	}

	// But an advertised list that no longer contains our path means it is gone.
	h.mgr.SetPeers([]Peer{{Key: h.peer.pub, Candidates: []netip.AddrPort{addrA}}})
	if s, _ := h.mgr.State(key); s != StateIdle {
		t.Fatalf("state = %s, want Idle once the candidate disappeared", s)
	}
}

func TestProbesFromUnknownPeersAreIgnored(t *testing.T) {
	h := newHarness(t, addrB)
	stranger := newKeys(t)
	frame := Pong(stranger.priv, stranger.pub, h.mgr.cfg.Public, time.Now())
	if h.mgr.Handle(addrA, frame) {
		t.Fatal("a probe from an unknown Node was accepted")
	}
}
