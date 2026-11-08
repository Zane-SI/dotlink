package relay

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Packet is one datagram that arrived on the Agent's single UDP socket.
//
// Relay is true when it came through the Relay, in which case Key is the
// sender's public key as proven by the Relay's table — not as claimed by the
// packet. When Relay is false the packet came straight from Addr, which is
// what the hole-punching path will use.
type Packet struct {
	Relay   bool
	Key     [32]byte
	Addr    netip.AddrPort
	Payload []byte
}

// extraReadDelay keeps a persistently failing socket from spinning the CPU.
const extraReadDelay = 10 * time.Millisecond

// Config is what an Agent needs to talk to a Relay.
type Config struct {
	Relay         netip.AddrPort
	Pub           [32]byte // this Agent's WireGuard public key
	Secret        []byte   // Relay secret, from the Peer Map
	Logger        *slog.Logger
	HelloInterval time.Duration // 0 means DefaultHelloInterval
	Now           func() time.Time
}

// Client keeps an Agent registered with a Relay and moves frames both ways.
//
// Registration is periodic on purpose: a Relay that restarts forgets its
// table, and the next HELLO puts us back in it. That is the whole reconnect
// story — no handshakes, no backoff, no state to lose.
type Client struct {
	cfg     Config
	pc      net.PacketConn
	log     *slog.Logger
	packets chan Packet
	done    chan struct{}
	once    sync.Once

	mu         sync.Mutex
	registered bool
	lastOK     time.Time
}

// NewClient takes ownership of pc and starts reading. The socket is shared
// with whatever else the Agent does on the same port, so non-Dotlink frames
// are delivered with Relay=false rather than dropped.
func NewClient(pc net.PacketConn, cfg Config) (*Client, error) {
	if !cfg.Relay.IsValid() {
		return nil, errors.New("relay: no relay address")
	}
	c := &Client{
		cfg:     cfg,
		pc:      pc,
		log:     cfg.Logger,
		packets: make(chan Packet, 128),
		done:    make(chan struct{}),
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	if c.cfg.HelloInterval <= 0 {
		c.cfg.HelloInterval = DefaultHelloInterval
	}
	if c.cfg.Now == nil {
		c.cfg.Now = time.Now
	}
	go c.readLoop()
	go c.helloLoop()
	return c, nil
}

func (c *Client) Packets() <-chan Packet { return c.packets }

func (c *Client) LocalAddr() netip.AddrPort {
	ap, _ := addrPort(c.pc.LocalAddr())
	return ap
}

// Registered reports whether the Relay has acknowledged us recently enough to
// be forwarding. It is the Relay-side half of "am I online".
func (c *Client) Registered() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.registered
}

func (c *Client) LastOK() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastOK
}

// SendTo sends payload to key through the Relay.
func (c *Client) SendTo(key [32]byte, payload []byte) error {
	return c.send(Data(nil, key, payload))
}

// SendToAddr sends a bare datagram to a peer address, which is what the
// direct path needs: from the Relay's point of view it is just another
// WireGuard packet.
func (c *Client) SendToAddr(addr netip.AddrPort, payload []byte) error {
	_, err := c.pc.WriteTo(payload, net.UDPAddrFromAddrPort(addr))
	return err
}

func (c *Client) send(frame []byte) error {
	_, err := c.pc.WriteTo(frame, net.UDPAddrFromAddrPort(c.cfg.Relay))
	return err
}

func (c *Client) Close() error {
	var err error
	c.once.Do(func() {
		close(c.done)
		err = c.pc.Close()
	})
	return err
}

func (c *Client) readLoop() {
	defer close(c.packets)
	buf := make([]byte, 64*1024)
	for {
		n, from, err := c.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-c.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A Relay that restarted, or a firewall that answered with ICMP
			// port-unreachable, surfaces as a read error on some platforms.
			// Dropping the socket there would silently end the tunnel for
			// good, so keep reading.
			c.log.Warn("relay: read", "err", err)
			time.Sleep(extraReadDelay)
			continue
		}
		addr, ok := addrPort(from)
		if !ok {
			continue
		}
		if !c.dispatch(buf[:n], addr) {
			return
		}
	}
}

// dispatch handles one datagram and reports whether the loop should continue.
func (c *Client) dispatch(f []byte, from netip.AddrPort) bool {
	kind, isOurs := KindOf(f)
	if !isOurs {
		return c.deliver(Packet{Addr: from, Payload: f, Relay: false})
	}
	switch kind {
	case KindHelloOK:
		ts, err := ParseHelloOK(f)
		if err != nil {
			return true
		}
		c.mu.Lock()
		was := c.registered
		c.registered, c.lastOK = true, c.cfg.Now()
		c.mu.Unlock()
		if !was {
			c.log.Info("relay: registered", "relay", c.cfg.Relay, "relay_time", ts)
		}
	case KindData:
		src, payload, err := ParseData(f)
		if err != nil {
			return true
		}
		return c.deliver(Packet{Key: src, Addr: from, Payload: payload, Relay: true})
	case KindError:
		code, msg, err := ParseError(f)
		if err != nil {
			return true
		}
		c.log.Warn("relay: rejected", "code", code, "msg", msg)
	}
	return true
}

func (c *Client) deliver(p Packet) bool {
	p.Payload = append([]byte(nil), p.Payload...)
	select {
	case c.packets <- p:
		return true
	case <-c.done:
		return false
	default:
		// A full queue means the data path is not draining; dropping is what
		// UDP does anyway.
		c.log.Debug("relay: dropping packet, queue full")
		return true
	}
}

func (c *Client) helloLoop() {
	t := time.NewTicker(c.cfg.HelloInterval)
	defer t.Stop()
	c.hello()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		}
		// Missing three acknowledgements in a row means the Relay is not
		// taking our HELLOs: report it as not registered until it answers.
		c.mu.Lock()
		stale := c.registered && c.cfg.Now().Sub(c.lastOK) > 3*c.cfg.HelloInterval
		if stale {
			c.registered = false
		}
		c.mu.Unlock()
		if stale {
			c.log.Warn("relay: lost registration", "relay", c.cfg.Relay)
		}
		c.hello()
	}
}

func (c *Client) hello() {
	if err := c.send(Hello(nil, c.cfg.Pub, c.cfg.Now(), c.cfg.Secret)); err != nil {
		c.log.Warn("relay: hello", "relay", c.cfg.Relay, "err", err)
	}
}
