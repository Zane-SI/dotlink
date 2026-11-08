package tunnel

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/Zane-SI/dotlink/internal/relay"
	"golang.zx2c4.com/wireguard/conn"
)

// keyPrefix marks an endpoint string that names a Node by public key rather
// than by address. WireGuard hands these strings to us verbatim through the
// UAPI, so the prefix is how a Relay destination survives a round trip through
// WireGuard's own endpoint bookkeeping.
const keyPrefix = "pk:"

// Bind is the seam between wireguard-go and the Relay. It implements
// conn.Bind, so WireGuard believes it is talking to a normal UDP socket while
// every datagram actually goes through the Relay addressed by public key.
//
// The socket itself is owned by relay.Client: one socket carries both the
// Relay link and (from #3 on) direct peer traffic, so the NAT mapping built by
// a successful hole punch is immediately usable by WireGuard.
type Bind struct {
	client *relay.Client
	router Router

	mu     sync.Mutex
	closed chan struct{}
}

// Router answers "does this peer have a direct path right now?". It is
// implemented by punch.Manager; a nil Router means every peer goes through the
// Relay, which is what the tests that only exercise the Relay use.
type Router interface {
	// Route returns the direct address for key, if one is in place.
	Route(key [32]byte) (netip.AddrPort, bool)
	// Touch records that traffic wants to reach key, starting a punch.
	Touch(key [32]byte)
}

func NewBind(c *relay.Client, router Router) *Bind {
	return &Bind{client: c, router: router}
}

// Open hands WireGuard a receive function wired to the Relay. The socket
// already exists and outlives the Bind: WireGuard calls Close and Open again
// on every rebind, and closing the shared socket there would tear down the
// Relay link (and the NAT mapping that #3 will punch).
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	done := make(chan struct{})
	b.closed = done
	return []conn.ReceiveFunc{func(buffers [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		return b.receive(done, buffers, sizes, eps)
	}}, b.client.LocalAddr().Port(), nil
}

// Close stops this Bind without stopping the Relay client. The owner of the
// Client closes it.
func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed != nil {
		close(b.closed)
		b.closed = nil
	}
	return nil
}

func (b *Bind) SetMark(uint32) error { return nil }

func (b *Bind) BatchSize() int { return 1 }

func (b *Bind) receive(done <-chan struct{}, buffers [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	select {
	case <-done:
		return 0, net.ErrClosed
	case p, ok := <-b.client.Packets():
		if !ok {
			return 0, net.ErrClosed
		}
		sizes[0] = copy(buffers[0], p.Payload)
		if p.Relay {
			eps[0] = &keyEndpoint{key: p.Key}
		} else {
			eps[0] = addrEndpoint(p.Addr)
		}
		return 1, nil
	}
}

func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	switch e := ep.(type) {
	case *keyEndpoint:
		// The path can change between any two packets, so every send asks the
		// router. Nothing is reconfigured: the peer stays "pk:<hex>" in
		// WireGuard's bookkeeping and only this hop knows where it goes.
		if b.router != nil {
			b.router.Touch(e.key)
		}
		var direct netip.AddrPort
		if b.router != nil {
			direct, _ = b.router.Route(e.key)
		}
		for _, buf := range bufs {
			var err error
			if direct.IsValid() {
				err = b.client.SendToAddr(direct, buf)
			} else {
				err = b.client.SendTo(e.key, buf)
			}
			if err != nil {
				return err
			}
		}
		return nil
	case addrEndpoint:
		for _, buf := range bufs {
			if err := b.client.SendToAddr(netip.AddrPort(e), buf); err != nil {
				return err
			}
		}
		return nil
	default:
		return conn.ErrWrongEndpointType
	}
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if rest, ok := strings.CutPrefix(s, keyPrefix); ok {
		raw, err := hex.DecodeString(rest)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", s, err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("endpoint %q: key is %d bytes, want 32", s, len(raw))
		}
		var k [32]byte
		copy(k[:], raw)
		return &keyEndpoint{key: k}, nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("endpoint %q: %w", s, err)
	}
	return addrEndpoint(ap), nil
}

// keyEndpoint is a Node reached through the Relay.
type keyEndpoint struct {
	key [32]byte
}

func (e *keyEndpoint) ClearSrc()           {}
func (e *keyEndpoint) SrcToString() string { return "" }
func (e *keyEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *keyEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e *keyEndpoint) DstToBytes() []byte  { return e.key[:] }
func (e *keyEndpoint) DstToString() string { return keyPrefix + hex.EncodeToString(e.key[:]) }

// addrEndpoint is a Node reached at a real address, which is what a successful
// hole punch produces.
type addrEndpoint netip.AddrPort

func (e addrEndpoint) ClearSrc()           {}
func (e addrEndpoint) SrcToString() string { return "" }
func (e addrEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e addrEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e addrEndpoint) DstToString() string { return netip.AddrPort(e).String() }

func (e addrEndpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}
