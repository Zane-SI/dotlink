// Package link owns the choice between the two Relay transports: the direct
// UDP Relay (fast, and the only path that can be punched) and DERP over TLS
// (slower, but survives a network that throttles or blocks UDP).
//
// The Agent keeps both alive at once. The switch is a decision made per send,
// so a failing transport costs nothing more than the packets that were already
// in flight.
package link

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/Zane-SI/dotlink/internal/derp"
	"github.com/Zane-SI/dotlink/internal/relay"
)

// Backend is one way to reach the Relay. Both transports implement it.
type Backend interface {
	SendTo(key [32]byte, payload []byte) error
	Registered() bool
	Close() error
}

// UDPBackend is the socket-backed transport. It also owns the NAT mapping the
// punch negotiated, which is why direct sends stay here even in DERP mode.
type UDPBackend interface {
	Backend
	SendToAddr(addr netip.AddrPort, payload []byte) error
	LocalAddr() netip.AddrPort
	Packets() <-chan relay.Packet
}

// DERPBackend is the TLS transport.
type DERPBackend interface {
	Backend
	Packets() <-chan derp.Packet
}

// Mode names the transport in use.
type Mode string

const (
	ModeUDP  Mode = "udp"
	ModeDERP Mode = "derp"
)

const (
	// DefaultFailAfter is how long UDP may stay unregistered before we stop
	// waiting for it. Long enough to ride out a Relay restart, short enough
	// that a blocked port is noticed inside a minute.
	DefaultFailAfter = 12 * time.Second
	// pollInterval is how often the mode is reconsidered. It is not the
	// switching cost: switching costs nothing.
	pollInterval = time.Second
)

// Link multiplexes the two Relay transports.
type Link struct {
	udp  UDPBackend
	derp DERPBackend
	log  *slog.Logger

	// FailAfter is how long UDP must be unregistered before DERP takes over.
	FailAfter time.Duration

	mu        sync.Mutex
	mode      Mode
	since     time.Time
	downFor   time.Time // when UDP was first seen unregistered
	packets   chan relay.Packet
	closed    chan struct{}
	closeOnce sync.Once
}

// New starts the packet pumps. udp is required; d may be nil, in which case
// the Link is a thin pass-through.
func New(udp UDPBackend, d DERPBackend, logger *slog.Logger) *Link {
	if logger == nil {
		logger = slog.Default()
	}
	l := &Link{
		udp:       udp,
		derp:      d,
		log:       logger,
		FailAfter: DefaultFailAfter,
		mode:      ModeUDP,
		since:     time.Now(),
		packets:   make(chan relay.Packet, 256),
		closed:    make(chan struct{}),
	}
	go l.pumpUDP()
	if d != nil {
		go l.pumpDERP(d)
	}
	return l
}

// SetDERP installs (or replaces) the DERP backend after a reconnect.
func (l *Link) SetDERP(d DERPBackend) {
	l.mu.Lock()
	old := l.derp
	l.derp = d
	l.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	if d != nil {
		go l.pumpDERP(d)
	}
}

// Mode reports which transport is carrying relayed traffic.
func (l *Link) Mode() Mode {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.mode
}

// LocalAddr is the UDP socket's address, which is where punches are aimed.
func (l *Link) LocalAddr() netip.AddrPort { return l.udp.LocalAddr() }

// Packets is the merged stream from both transports.
func (l *Link) Packets() <-chan relay.Packet { return l.packets }

// SendTo forwards one payload to key over the active transport.
func (l *Link) SendTo(key [32]byte, payload []byte) error {
	l.mu.Lock()
	mode, d := l.mode, l.derp
	l.mu.Unlock()
	switch {
	case mode == ModeDERP && d != nil:
		return d.SendTo(key, payload)
	default:
		return l.udp.SendTo(key, payload)
	}
}

// SendToAddr sends a bare datagram to a peer address. There is no DERP
// equivalent: a direct path is UDP by definition, so this always uses the
// socket the punch negotiated its mapping on.
func (l *Link) SendToAddr(addr netip.AddrPort, payload []byte) error {
	return l.udp.SendToAddr(addr, payload)
}

// Run reconsiders the transport until ctx is cancelled.
func (l *Link) Run(ctx context.Context) {
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.closed:
			return
		case <-t.C:
			l.decide(time.Now())
		}
	}
}

// decide is the whole switching policy, exported to the tests as Tick.
func (l *Link) decide(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.derp
	if d == nil {
		return
	}
	udpUp := l.udp.Registered()
	if udpUp {
		l.downFor = time.Time{}
		if l.mode != ModeUDP {
			l.mode, l.since = ModeUDP, now
			l.log.Info("link: back on the udp relay")
		}
		return
	}
	if l.downFor.IsZero() {
		l.downFor = now
	}
	if l.mode == ModeUDP && now.Sub(l.downFor) >= l.FailAfter && d.Registered() {
		l.mode, l.since = ModeDERP, now
		l.log.Warn("link: udp relay unreachable, falling back to derp", "down_for", now.Sub(l.downFor).Round(time.Second))
	}
}

// Tick advances the switching policy. Tests drive it directly.
func (l *Link) Tick() { l.decide(time.Now()) }

// Close stops the pumps and both transports.
func (l *Link) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	err := l.udp.Close()
	l.mu.Lock()
	d := l.derp
	l.mu.Unlock()
	if d != nil {
		if derr := d.Close(); err == nil {
			err = derr
		}
	}
	return err
}

func (l *Link) pumpUDP() {
	for {
		select {
		case <-l.closed:
			return
		case p, ok := <-l.udp.Packets():
			if !ok {
				return
			}
			if !l.deliver(p) {
				return
			}
		}
	}
}

func (l *Link) pumpDERP(d DERPBackend) {
	for {
		select {
		case <-l.closed:
			return
		case p, ok := <-d.Packets():
			if !ok {
				return
			}
			// DERP is a Relay in every sense the data path cares about: the
			// source key is the server's word, and the path is not direct.
			if !l.deliver(relay.Packet{Relay: true, Key: p.Key, Payload: p.Payload}) {
				return
			}
		}
	}
}

func (l *Link) deliver(p relay.Packet) bool {
	select {
	case l.packets <- p:
		return true
	case <-l.closed:
		return false
	}
}

// DERPUp reports whether the TLS fallback is connected and answering.
func (l *Link) DERPUp() bool {
	l.mu.Lock()
	d := l.derp
	l.mu.Unlock()
	return d != nil && d.Registered()
}
