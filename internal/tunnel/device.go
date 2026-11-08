package tunnel

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// DefaultKeepalive is deliberately 0 in relay-only mode.
//
// The Relay leg is one UDP flow per Agent, and the HELLO every 25s keeps its
// NAT mapping open — WireGuard keepalives would add nothing. Worse, turning
// them on makes both ends fire a handshake initiation at the same moment when
// they start together, and WireGuard keeps one handshake state per peer, so
// each side's response is rejected by the other until the retry timer fires.
// #3 revisits this: once there is a direct path to keep alive, the punch
// probes do it anyway.
const DefaultKeepalive = 0

// Peer is one Node as WireGuard needs to see it. Prefixes are the overlay
// address plus anything the Node routes for (a Subnet Router's LAN).
type Peer struct {
	Pub       [32]byte
	Prefixes  []netip.Prefix
	Keepalive int // seconds, 0 means DefaultKeepalive
}

type DeviceConfig struct {
	PrivateKey [32]byte
	Peers      []Peer
	Logger     *device.Logger // nil means errors only
}

// Device is a running WireGuard instance plus the peer set it was last given,
// so later updates can touch only what changed. A Node joining must not tear
// down everyone else's session.
type Device struct {
	dev *device.Device

	mu    sync.Mutex
	peers map[[32]byte][]netip.Prefix
}

// New takes ownership of tunDev: closing the returned Device closes the TUN,
// and a failed New closes it before returning.
//
// It builds a WireGuard device on top of an already-configured Bind and TUN.
// Everything WireGuard needs to know arrives through the UAPI string, which is
// the same path `wg setconf` uses — no private API, and the config can be
// dumped back out for debugging.
func New(tunDev tun.Device, bind conn.Bind, cfg DeviceConfig) (*Device, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = device.NewLogger(device.LogLevelError, "dotlink")
	}
	dev := device.NewDevice(tunDev, bind, logger)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%x\n", cfg.PrivateKey)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure device: %w", err)
	}
	d := &Device{dev: dev, peers: map[[32]byte][]netip.Prefix{}}
	if err := d.Apply(cfg.Peers); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring device up: %w", err)
	}
	return d, nil
}

// Dev exposes the underlying device for the one thing #3 needs: swapping a
// Peer's endpoint when the punch succeeds.
func (d *Device) Dev() *device.Device { return d.dev }

func (d *Device) Close() { d.dev.Close() }

// Apply brings the peer set up to date with peers, touching only the peers
// that appeared, disappeared or changed their prefixes.
func (d *Device) Apply(peers []Peer) error {
	d.mu.Lock()
	ops, next := peerOps(d.peers, peers)
	d.peers = next
	d.mu.Unlock()

	if ops == "" {
		return nil
	}
	if err := d.dev.IpcSet(ops); err != nil {
		return fmt.Errorf("apply peers: %w", err)
	}
	return nil
}

// RelayEndpoint is the UAPI endpoint string for a Node reached through the
// Relay.
func RelayEndpoint(pub [32]byte) string {
	return keyPrefix + hex.EncodeToString(pub[:])
}

// peerOps renders the minimal UAPI operations that turn prev into peers.
//
// Removals come first so a Node that changed its address is not briefly
// reachable at both. A peer whose prefixes changed keeps its endpoint and its
// session: only the AllowedIPs need rewriting.
func peerOps(prev map[[32]byte][]netip.Prefix, peers []Peer) (string, map[[32]byte][]netip.Prefix) {
	next := make(map[[32]byte][]netip.Prefix, len(peers))
	for _, p := range peers {
		next[p.Pub] = p.Prefixes
	}

	var b strings.Builder
	removed := make([][32]byte, 0, len(prev))
	for pub := range prev {
		if _, ok := next[pub]; !ok {
			removed = append(removed, pub)
		}
	}
	sortKeys(removed)
	for _, pub := range removed {
		fmt.Fprintf(&b, "public_key=%x\nremove=true\n", pub)
	}

	for _, p := range peers {
		before, seen := prev[p.Pub]
		switch {
		case !seen:
			fmt.Fprintf(&b, "public_key=%x\n", p.Pub)
			fmt.Fprintf(&b, "endpoint=%s\n", RelayEndpoint(p.Pub))
			if p.Keepalive > 0 {
				fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
			}
			for _, prefix := range p.Prefixes {
				fmt.Fprintf(&b, "allowed_ip=%s\n", prefix)
			}
		case !samePrefixes(before, p.Prefixes):
			fmt.Fprintf(&b, "public_key=%x\nremove_allowed_ips=true\n", p.Pub)
			for _, prefix := range p.Prefixes {
				fmt.Fprintf(&b, "allowed_ip=%s\n", prefix)
			}
		}
	}
	return b.String(), next
}

func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sortKeys(keys [][32]byte) {
	sort.Slice(keys, func(i, j int) bool { return string(keys[i][:]) < string(keys[j][:]) })
}
