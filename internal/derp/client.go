package derp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Packet is one framed payload that arrived for us.
type Packet struct {
	Key     [32]byte
	Payload []byte
}

// Client is one TLS connection to a DERP server, addressed by public key.
//
// It is the fallback path: packets still get the same treatment as the UDP
// Relay (forwarded blind), only the transport differs.
type Client struct {
	conn net.Conn
	bw   *bufio.Reader
	key  [32]byte
	log  *slog.Logger

	packets chan Packet
	out     chan outFrame
	done    chan struct{}

	mu        sync.Mutex
	serverKey [32]byte
	lastPong  time.Time
	connected bool

	closeOnce sync.Once
}

// Config is what Dial needs.
type Config struct {
	// Addr is host:port of the DERP endpoint, e.g. relay.example.com:8443.
	Addr string
	// TLS is the client configuration. ServerName is filled in from Addr when
	// empty, so certificate verification works without extra setup.
	TLS *tls.Config
	// Key is this Node's public key, the identity the server routes by.
	Key [32]byte
	// Logger may be nil.
	Logger *slog.Logger
	// KeepAlive is how often to tell the server we are still here.
	KeepAlive time.Duration
	// PingInterval is how often to measure liveness. A connection that stops
	// answering pings is not registered, whatever TCP thinks.
	PingInterval time.Duration
}

const (
	defaultKeepAlive = 25 * time.Second
	// protocolPing is how often we measure the path. Named apart from the
	// server's own ping interval: they are different decisions.
	protocolPing = 15 * time.Second
	// registeredWindow is how long a Pong keeps us "registered". Two missed
	// pings means the path is gone even if the socket has not noticed.
	registeredWindow = 45 * time.Second
)

// Dial connects, performs the upgrade, and starts the read and write loops.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Addr == "" {
		return nil, errors.New("derp: no address")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.KeepAlive <= 0 {
		cfg.KeepAlive = defaultKeepAlive
	}
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = protocolPing
	}

	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("derp: %q: %w", cfg.Addr, err)
	}
	tlsCfg := cfg.TLS
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	} else {
		tlsCfg = tlsCfg.Clone()
	}
	if tlsCfg.ServerName == "" {
		// A certificate is issued to a name, not to an address; using the
		// dialed host is what makes verification work by default.
		tlsCfg.ServerName = host
	}

	d := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}

	// The upgrade is a plain HTTP request; the server answers 101 and the
	// connection stops being HTTP.
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: %s\r\nConnection: Upgrade\r\n\r\n", Path, host, UpgradeHeader)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	bw := bufio.NewReader(conn)
	resp, err := http.ReadResponse(bw, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("derp: upgrade: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("derp: upgrade returned %s", resp.Status)
	}

	c := &Client{
		conn:    conn,
		bw:      bw,
		key:     cfg.Key,
		log:     cfg.Logger,
		packets: make(chan Packet, 128),
		out:     make(chan outFrame, 256),
		done:    make(chan struct{}),
		// A completed handshake counts as reachable until the first ping
		// says otherwise. Waiting for a Pong before admitting we are
		// connected would leave the fallback idle for a full ping interval.
		connected: true,
		lastPong:  time.Now(),
	}
	typ, body, err := readFrame(bw)
	if err != nil || typ != frameServerKey || len(body) != keyLen {
		conn.Close()
		return nil, fmt.Errorf("derp: no server key: %w", err)
	}
	c.mu.Lock()
	copy(c.serverKey[:], body)
	c.mu.Unlock()

	// Identify ourselves, then let the loops run.
	if err := writeFrame(conn, frameClientInfo, clientInfoBody(cfg.Key)); err != nil {
		conn.Close()
		return nil, err
	}
	go c.writeLoop()
	go c.readLoop()
	go c.keepLoop(cfg.KeepAlive, cfg.PingInterval)
	return c, nil
}

// ServerKey is the identity the server advertised during the handshake.
func (c *Client) ServerKey() [32]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serverKey
}

// SendTo forwards payload to dst through the server.
func (c *Client) SendTo(dst [32]byte, payload []byte) error {
	body := sendPacketBody(dst, payload)
	select {
	case c.out <- outFrame{typ: frameSendPacket, payload: body}:
		return nil
	case <-c.done:
		return ErrClientClosed
	case <-time.After(30 * time.Second):
		// A Relay that cannot drain one frame in 30 seconds is not a Relay we
		// should silently drop traffic for.
		return errors.New("derp: send queue is stuck")
	}
}

// Packets is the stream of payloads addressed to us.
func (c *Client) Packets() <-chan Packet { return c.packets }

// Registered reports whether the server is answering our pings. TCP being
// connected is not enough: a path can be black-holed for minutes before the
// socket gives up.
func (c *Client) Registered() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected && time.Since(c.lastPong) < registeredWindow
}

// Close tears down the connection.
func (c *Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		err = c.conn.Close()
	})
	return err
}

func (c *Client) readLoop() {
	defer close(c.packets)
	defer func() {
		// The stream is gone, so stop claiming to be reachable: the Agent has
		// to fall back to UDP, and a stale "registered" would keep it here.
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()
		_ = c.Close()
	}()
	for {
		typ, body, err := readFrame(c.bw)
		if err != nil {
			return
		}
		switch typ {
		case frameRecvPacket:
			src, payload, err := parseRecvPacket(body)
			if err != nil {
				continue
			}
			select {
			case c.packets <- Packet{Key: src, Payload: payload}:
			case <-c.done:
				return
			}
		case framePong:
			c.mu.Lock()
			c.connected, c.lastPong = true, time.Now()
			c.mu.Unlock()
		case framePing:
			if len(body) == pingLen {
				c.enqueue(outFrame{typ: framePong, payload: body})
			}
		case frameRestarting:
			// The server is going away on purpose. Stop claiming to be
			// registered so the Agent switches back to UDP if it can.
			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()
		case frameHealth:
			c.log.Warn("derp: server reports a problem", "detail", string(body))
		}
	}
}

func (c *Client) writeLoop() {
	for {
		select {
		case <-c.done:
			return
		case f := <-c.out:
			_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := writeFrame(c.conn, f.typ, f.payload); err != nil {
				_ = c.Close()
				return
			}
		}
	}
}

func (c *Client) keepLoop(keepAlive, ping time.Duration) {
	ka := time.NewTicker(keepAlive)
	defer ka.Stop()
	pi := time.NewTicker(ping)
	defer pi.Stop()
	// Ask once right away: the answer is what turns "connected" into
	// "registered" for good.
	c.enqueue(outFrame{typ: framePing, payload: make([]byte, pingLen)})
	for {
		select {
		case <-c.done:
			return
		case <-ka.C:
			c.enqueue(outFrame{typ: frameKeepAlive})
		case <-pi.C:
			c.enqueue(outFrame{typ: framePing, payload: make([]byte, pingLen)})
		}
	}
}

func (c *Client) enqueue(f outFrame) {
	select {
	case c.out <- f:
	case <-c.done:
	default:
	}
}
