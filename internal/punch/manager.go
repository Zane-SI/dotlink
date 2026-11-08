package punch

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// State is where one peer sits on the relay-or-direct question.
type State string

const (
	// StateIdle means nobody has tried to reach this peer yet: no traffic, no
	// probes, no cost.
	StateIdle State = "Idle"
	// StateProbing means probe rounds are in flight.
	StateProbing State = "Probing"
	// StateDirect means a Pong arrived and packets take the direct path.
	StateDirect State = "Direct"
	// StateRelayed means probing gave up; traffic takes the Relay, and a probe
	// round is retried every RetryInterval without interrupting it.
	StateRelayed State = "Relayed"
)

// Transport is how the Manager puts a probe on the wire. The data path owns
// the socket; the Manager only knows addresses.
type Transport interface {
	SendProbe(addr netip.AddrPort, frame []byte) error
}

// Peer is what the Manager needs to know about another Node.
type Peer struct {
	Key        [32]byte
	Candidates []netip.AddrPort
}

// Config is what a Manager needs.
type Config struct {
	Private   [32]byte
	Public    [32]byte
	Transport Transport
	Logger    *slog.Logger
	Now       func() time.Time
	Skew      time.Duration // accepted clock difference on probes
	Interval  time.Duration // between probe rounds
	Rounds    int           // probe rounds before giving up
	Keepalive time.Duration // between pings on a direct path
	MaxMisses int           // unanswered keepalives before dropping to relay
	Retry     time.Duration // between probe rounds while relayed
	OnPath    func(key [32]byte, state State)
}

// Defaults chosen from the spec: 200ms × 5 rounds to punch, 25s keepalive,
// three misses to give up, and a 60s retry that never disturbs live traffic.
const (
	DefaultInterval  = 200 * time.Millisecond
	DefaultRounds    = 5
	DefaultKeepalive = 25 * time.Second
	DefaultMaxMisses = 3
	DefaultRetry     = 60 * time.Second
	DefaultSkew      = time.Minute
	tickInterval     = 20 * time.Millisecond
)

// Manager runs one hole-punch state machine per peer.
type Manager struct {
	cfg Config
	log *slog.Logger

	mu    sync.Mutex
	peers map[[32]byte]*peer
}

type peer struct {
	key     [32]byte
	cands   []netip.AddrPort
	state   State
	round   int
	misses  int
	nextAct time.Time // next time this peer needs attention
	sentAt  time.Time // when the last ping went out
	direct  netip.AddrPort
	rtt     time.Duration
}

// New builds a Manager. Zero values in cfg fall back to the defaults above.
func New(cfg Config) *Manager {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Skew <= 0 {
		cfg.Skew = DefaultSkew
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Rounds <= 0 {
		cfg.Rounds = DefaultRounds
	}
	if cfg.Keepalive <= 0 {
		cfg.Keepalive = DefaultKeepalive
	}
	if cfg.MaxMisses <= 0 {
		cfg.MaxMisses = DefaultMaxMisses
	}
	if cfg.Retry <= 0 {
		cfg.Retry = DefaultRetry
	}
	return &Manager{cfg: cfg, log: cfg.Logger, peers: map[[32]byte]*peer{}}
}

// SetOnPath installs the callback that fires when a peer changes path. The
// daemon uses it to refresh its status snapshot the moment a punch lands,
// instead of waiting for the next heartbeat.
func (m *Manager) SetOnPath(fn func(key [32]byte, state State)) {
	m.mu.Lock()
	m.cfg.OnPath = fn
	m.mu.Unlock()
}

// SetPeers replaces the peer table with what the latest Peer Map says. Paths
// already in place survive: a map refresh must not drop a working tunnel.
func (m *Manager) SetPeers(peers []Peer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := make(map[[32]byte]*peer, len(peers))
	for _, p := range peers {
		if old, ok := m.peers[p.Key]; ok {
			old.cands = dedupe(p.Candidates)
			if old.state == StateDirect && !contains(old.cands, old.direct) {
				// The address we punched through is no longer advertised.
				old.state, old.direct = StateIdle, netip.AddrPort{}
			}
			next[p.Key] = old
			continue
		}
		next[p.Key] = &peer{key: p.Key, state: StateIdle, cands: dedupe(p.Candidates)}
	}
	m.peers = next
}

// Touch tells the Manager that traffic wants to reach key. It is what turns an
// Idle peer into a Probing one: punching costs packets, so nobody punches
// before something actually wants to talk.
func (m *Manager) Touch(key [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[key]
	if !ok || p.state != StateIdle || len(p.cands) == 0 {
		return
	}
	p.state = StateProbing
	p.round = 0
	p.nextAct = m.cfg.Now()
}

// Route reports the direct address for key, if one is in place. The data path
// calls it on every send, so a path change takes effect on the next packet
// without touching WireGuard's configuration.
func (m *Manager) Route(key [32]byte) (netip.AddrPort, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[key]
	if !ok || p.state != StateDirect {
		return netip.AddrPort{}, false
	}
	return p.direct, true
}

// Handle consumes a probe frame that arrived from addr. It reports whether the
// frame was ours; the data path only calls it for packets that carry the
// magic, so a false means "malformed, drop it".
func (m *Manager) Handle(from netip.AddrPort, frame []byte) bool {
	pr, err := Open(frame, m.cfg.Private, m.cfg.Public, m.cfg.Now(), m.cfg.Skew)
	if err != nil {
		m.log.Debug("punch: bad probe", "from", from, "err", err)
		return false
	}

	now := m.cfg.Now()
	var (
		reply  []byte
		change bool
		onPath func([32]byte, State)
	)
	m.mu.Lock()
	p, ok := m.peers[pr.Sender]
	if !ok {
		m.mu.Unlock()
		m.log.Debug("punch: probe from an unknown peer", "from", from)
		return false
	}
	if pr.Kind == KindPing {
		reply = Pong(m.cfg.Private, m.cfg.Public, pr.Sender, pr.SentAt)
	}
	// Any authenticated probe at a real address proves the path both ways: the
	// peer had to reach us to be here. A Pong is the explicit signal the spec
	// asks for, and a Ping counts too because it is the same evidence.
	wasDirect, prev := p.state == StateDirect, p.direct
	p.state, p.direct, p.misses = StateDirect, from, 0
	p.nextAct = now.Add(m.cfg.Keepalive)
	if pr.Kind == KindPong && !p.sentAt.IsZero() {
		if d := now.Sub(p.sentAt); d >= 0 && d < m.cfg.Keepalive {
			p.rtt = d
		}
	}
	change = !wasDirect || prev != from
	onPath = m.cfg.OnPath
	m.mu.Unlock()

	if reply != nil {
		// Answering from the same socket is the point: the address the peer
		// sees on our reply is the mapping its probes should target.
		if err := m.cfg.Transport.SendProbe(from, reply); err != nil {
			m.log.Debug("punch: pong", "to", from, "err", err)
		}
	}
	if change {
		m.log.Info("punch: path is direct", "peer", hexKey(pr.Sender), "addr", from)
		if onPath != nil {
			onPath(pr.Sender, StateDirect)
		}
	}
	return true
}

// Run ticks the state machines until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Tick()
		}
	}
}

// State reports the current path state and round-trip time for key.
func (m *Manager) State(key [32]byte) (State, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.peers[key]
	if !ok {
		return StateIdle, 0
	}
	return p.state, p.rtt
}

// Tick advances every peer that is due. It is exported so tests can drive the
// clock instead of sleeping.
//
// Probes are collected under the lock and sent after it is released: the
// transport may answer synchronously (a loopback in a test, or a peer on the
// same host), and re-entering the manager from inside Send would deadlock.
func (m *Manager) Tick() {
	now := m.cfg.Now()
	var out []probeOut
	var events []pathEvent
	m.mu.Lock()
	for _, p := range m.peers {
		if now.Before(p.nextAct) {
			continue
		}
		switch p.state {
		case StateIdle:
			// Nothing wants this peer yet.
		case StateProbing:
			if p.round >= m.cfg.Rounds {
				p.state = StateRelayed
				p.nextAct = now.Add(m.cfg.Retry)
				p.round = 0
				m.log.Debug("punch: giving up, using the relay", "peer", hexKey(p.key))
				continue
			}
			out = append(out, m.probeRoundLocked(p, now)...)
		case StateDirect:
			if p.misses >= m.cfg.MaxMisses {
				p.state = StateRelayed
				p.round = 0
				p.misses = 0
				p.nextAct = now.Add(m.cfg.Retry)
				m.log.Info("punch: direct path went quiet, back on the relay", "peer", hexKey(p.key))
				events = append(events, pathEvent{key: p.key, state: StateRelayed})
				continue
			}
			p.misses++
			p.sentAt = now
			p.nextAct = now.Add(m.cfg.Keepalive)
			out = append(out, m.sendPingsLocked(p)...)
		case StateRelayed:
			// A retry round: one burst, then back to waiting. Traffic keeps
			// flowing over the Relay the whole time.
			p.state = StateProbing
			p.round = 0
			out = append(out, m.probeRoundLocked(p, now)...)
		}
	}
	onPath := m.cfg.OnPath
	m.mu.Unlock()

	for _, e := range events {
		if onPath != nil {
			onPath(e.key, e.state)
		}
	}
	for _, o := range out {
		if err := m.cfg.Transport.SendProbe(o.addr, o.frame); err != nil {
			m.log.Debug("punch: probe", "to", o.addr, "err", err)
		}
	}
}

func (m *Manager) probeRoundLocked(p *peer, now time.Time) []probeOut {
	p.round++
	p.sentAt = now
	p.nextAct = now.Add(m.cfg.Interval)
	return m.sendPingsLocked(p)
}

func (m *Manager) sendPingsLocked(p *peer) []probeOut {
	targets := p.cands
	if p.state == StateDirect {
		targets = []netip.AddrPort{p.direct}
	}
	out := make([]probeOut, 0, len(targets))
	for _, addr := range targets {
		// One seal per packet: the nonce is random, so two probes for the same
		// round are not linkable to a passive observer.
		out = append(out, probeOut{addr: addr, frame: Ping(m.cfg.Private, m.cfg.Public, p.key, m.cfg.Now())})
	}
	return out
}

type pathEvent struct {
	key   [32]byte
	state State
}

type probeOut struct {
	addr  netip.AddrPort
	frame []byte
}

func contains(list []netip.AddrPort, want netip.AddrPort) bool {
	for _, a := range list {
		if a == want {
			return true
		}
	}
	return false
}

// dedupe keeps candidate order (the map's order is the peer's preference) but
// drops repeats: a Node that reports the same address twice should not double
// our probe traffic.
func dedupe(addrs []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, a := range addrs {
		if a.IsValid() && !contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func hexKey(k [32]byte) string {
	return hex.EncodeToString(k[:])
}
