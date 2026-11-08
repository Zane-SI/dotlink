package relay

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Defaults chosen so that a Relay restart is invisible: an Agent re-registers
// every HelloInterval, and a registration dies after TTL of silence.
const (
	DefaultHelloInterval = 25 * time.Second
	DefaultSkew          = time.Minute
	DefaultTTL           = 90 * time.Second
)

// Server is the Relay. It keeps one table — key → UDP address — and forwards
// frames between the entries. It holds no Node state, no flow state and no
// keys: every payload it moves is already end-to-end encrypted by WireGuard.
type Server struct {
	Secret []byte           // shared with Agents; signs HELLOs
	Logger *slog.Logger     // nil means stderr at info
	Now    func() time.Time // nil means time.Now
	Skew   time.Duration    // HELLO freshness window, 0 means DefaultSkew
	TTL    time.Duration    // registration lifetime, 0 means DefaultTTL

	mu    sync.Mutex
	table map[[32]byte]registration
}

type registration struct {
	addr netip.AddrPort
	seen time.Time
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) skew() time.Duration {
	if s.Skew > 0 {
		return s.Skew
	}
	return DefaultSkew
}

func (s *Server) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return DefaultTTL
}

// Serve reads frames from pc until it is closed. The caller owns the socket,
// so tests can run a Relay on an ephemeral port.
func (s *Server) Serve(pc net.PacketConn) error {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		addr, ok := addrPort(from)
		if !ok {
			continue
		}
		// The frame is only valid for this iteration; Data aliases buf.
		s.handle(pc, buf[:n], addr)
	}
}

func (s *Server) handle(pc net.PacketConn, f []byte, from netip.AddrPort) {
	kind, ok := KindOf(f)
	if !ok {
		// Not ours: a misrouted WireGuard packet or a scanner. Ignore.
		return
	}
	switch kind {
	case KindHello:
		pub, _, err := ParseHello(f, s.Secret, s.now(), s.skew())
		if err != nil {
			// The reply is smaller than the request, so answering cannot be
			// used to amplify.
			write(pc, Error(nil, ErrCodeBadFrame, err.Error()), from)
			return
		}
		s.register(pub, from)
		write(pc, HelloOK(nil, s.now()), from)
	case KindData:
		dst, payload, err := ParseData(f)
		if err != nil {
			write(pc, Error(nil, ErrCodeBadFrame, err.Error()), from)
			return
		}
		src, ok := s.senderOf(from)
		if !ok {
			// An unregistered address has no identity to attach. Dropping is
			// the only safe answer: forwarding it would let anyone inject
			// traffic under someone else's key.
			s.logger().Debug("relay: data from unregistered address", "from", from)
			return
		}
		target, ok := s.lookup(dst)
		if !ok {
			s.logger().Debug("relay: no route", "dst", dst, "from", src)
			write(pc, Error(nil, ErrCodeUnknownPeer, "no such peer"), from)
			return
		}
		write(pc, Data(nil, src, payload), target)
	}
}

func (s *Server) register(pub [32]byte, addr netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.table == nil {
		s.table = make(map[[32]byte]registration)
	}
	s.sweepLocked()
	if prev, ok := s.table[pub]; ok && prev.addr != addr {
		s.logger().Info("relay: key moved", "key", pub, "from", prev.addr, "to", addr)
	}
	s.table[pub] = registration{addr: addr, seen: s.now()}
}

// lookup returns the address a key is currently registered at, treating an
// entry older than TTL as gone.
func (s *Server) lookup(pub [32]byte) (netip.AddrPort, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.table[pub]
	if !ok || s.now().Sub(r.seen) > s.ttl() {
		return netip.AddrPort{}, false
	}
	return r.addr, true
}

func (s *Server) senderOf(addr netip.AddrPort) ([32]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for pub, r := range s.table {
		if r.addr == addr && s.now().Sub(r.seen) <= s.ttl() {
			return pub, true
		}
	}
	return [32]byte{}, false
}

func (s *Server) sweepLocked() {
	now := s.now()
	for pub, r := range s.table {
		if now.Sub(r.seen) > s.ttl() {
			delete(s.table, pub)
		}
	}
}

// Registered is how many keys the Relay can currently forward to.
func (s *Server) Registered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	return len(s.table)
}

func write(pc net.PacketConn, frame []byte, to netip.AddrPort) {
	if _, err := pc.WriteTo(frame, net.UDPAddrFromAddrPort(to)); err != nil {
		slog.Debug("relay: write failed", "to", to, "err", err)
	}
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.AddrPort(), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}
