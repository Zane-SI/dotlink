package derp

import (
	"bufio"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// UpgradeHeader is the value the DERP handshake puts in Connection/Upgrade.
// A stock derper speaks exactly this, so the same constant works on both ends.
const UpgradeHeader = "DERP"

// Path is where a DERP endpoint lives, matching upstream's /derp.
const Path = "/derp"

// Server is the TLS relay. It knows nothing about Dotlink's Control Plane: an
// Agent identifies itself with its public key and the server forwards frames
// between keys.
type Server struct {
	// Key is the identity advertised in the ServerKey frame. Clients may
	// ignore it; a stock derper uses it so clients can pin the server.
	Key [32]byte

	Logger *slog.Logger
	// PingInterval is how often the server pings an idle connection, which is
	// also how a half-open TCP connection gets noticed.
	PingInterval time.Duration
	// ReadTimeout closes a connection that has been silent for this long.
	ReadTimeout time.Duration

	mu     sync.Mutex
	conns  map[[32]byte]*serverConn
	closed bool
	ln     net.Listener
}

type serverConn struct {
	key  [32]byte
	conn net.Conn
	bw   *bufio.Reader
	out  chan outFrame

	closeOnce sync.Once
	ch        chan struct{}
}

type outFrame struct {
	typ     frameType
	payload []byte
}

const (
	defaultPingInterval = 20 * time.Second
	defaultReadTimeout  = 90 * time.Second
	// outQueue is how many frames may wait for one slow peer before the relay
	// drops them. Blocking the sender would let one stuck peer stall everyone.
	outQueue = 256
)

// NewServer builds a Server with the given advertised key.
func NewServer(key [32]byte, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		Key:          key,
		Logger:       logger,
		PingInterval: defaultPingInterval,
		ReadTimeout:  defaultReadTimeout,
		conns:        map[[32]byte]*serverConn{},
	}
}

// ServeTLS serves the DERP upgrade over TLS until Close is called. The caller
// owns the listener (so tests can bind port zero) and the certificate.
func (s *Server) ServeTLS(ln net.Listener, cfg *tls.Config) error {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	mux := http.NewServeMux()
	mux.Handle(Path, s.Handler())
	srv := &http.Server{
		Handler:           mux,
		TLSConfig:         cfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	err := srv.ServeTLS(ln, "", "")
	if s.isClosed() || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Handler is the HTTP side of the handshake: it accepts the upgrade and hands
// the raw connection to the relay. Mount it at Path.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != UpgradeHeader {
			http.Error(w, "expected a DERP upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "cannot hijack", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		// Write the response by hand: the connection is no longer HTTP.
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + UpgradeHeader + "\r\n\r\n")
		_ = rw.Flush()
		go s.runHijacked(conn, rw.Reader)
	})
}

// runHijacked takes over a connection that has just completed the upgrade.
func (s *Server) runHijacked(conn net.Conn, br *bufio.Reader) {
	if s.isClosed() {
		conn.Close()
		return
	}
	sc := &serverConn{conn: conn, bw: br, out: make(chan outFrame, outQueue), ch: make(chan struct{})}
	defer sc.close()

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := writeFrame(conn, frameServerKey, s.Key[:]); err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// The first frame must be ClientInfo: without a key there is nobody to
	// forward to and nothing to bill.
	typ, body, err := readFrame(br)
	if err != nil || typ != frameClientInfo {
		return
	}
	key, err := parseClientInfo(body)
	if err != nil {
		s.Logger.Debug("derp: bad client info", "err", err)
		return
	}
	sc.key = key
	s.register(key, sc)
	defer s.unregister(key, sc)
	s.Logger.Debug("derp: client connected", "key", shortKey(key))

	go sc.writeLoop()
	go sc.pingLoop(s.PingInterval, s.ReadTimeout)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		typ, body, err := readFrame(br)
		if err != nil {
			return
		}
		switch typ {
		case frameSendPacket:
			if len(body) < keyLen {
				continue
			}
			var dst [32]byte
			copy(dst[:], body[:keyLen])
			s.forward(dst, key, body[keyLen:])
		case framePing:
			if len(body) == pingLen {
				sc.send(framePong, body)
			}
		case frameKeepAlive:
			// Nothing to do: receiving it already reset the read deadline.
		case frameNotePreferred, frameHealth:
			// Accepted and ignored. Stock clients send these.
		}
	}
}

func (s *Server) forward(dst, src [32]byte, payload []byte) {
	s.mu.Lock()
	target := s.conns[dst]
	s.mu.Unlock()
	if target == nil {
		// A packet for a peer that is not here is not an error worth closing
		// the sender's connection over: the peer may simply be offline.
		return
	}
	if !target.send(frameRecvPacket, sendPacketBody(src, payload)) {
		s.Logger.Debug("derp: dropped a packet for a slow peer", "key", shortKey(dst))
	}
}

func (s *Server) register(key [32]byte, sc *serverConn) {
	s.mu.Lock()
	old := s.conns[key]
	s.conns[key] = sc
	s.mu.Unlock()
	if old != nil {
		// The same Node reconnected before the old socket died: the new one
		// wins, otherwise packets keep going to a dead TCP connection.
		old.close()
	}
}

func (s *Server) unregister(key [32]byte, sc *serverConn) {
	s.mu.Lock()
	if s.conns[key] == sc {
		delete(s.conns, key)
	}
	s.mu.Unlock()
}

// Registered reports how many clients are connected.
func (s *Server) Registered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Close stops the listener and every live connection.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.ln
	conns := make([]*serverConn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		c.close()
	}
	return nil
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (sc *serverConn) send(typ frameType, payload []byte) bool {
	select {
	case sc.out <- outFrame{typ: typ, payload: payload}:
		return true
	case <-sc.ch:
		return false
	default:
		return false
	}
}

func (sc *serverConn) writeLoop() {
	for {
		select {
		case <-sc.ch:
			return
		case f := <-sc.out:
			_ = sc.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := writeFrame(sc.conn, f.typ, f.payload); err != nil {
				sc.close()
				return
			}
		}
	}
}

func (sc *serverConn) pingLoop(every, timeout time.Duration) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	payload := make([]byte, pingLen)
	for {
		select {
		case <-sc.ch:
			return
		case <-t.C:
			if !sc.send(framePing, payload) {
				return
			}
		}
	}
}

func (sc *serverConn) close() {
	sc.closeOnce.Do(func() {
		close(sc.ch)
		_ = sc.conn.Close()
	})
}
