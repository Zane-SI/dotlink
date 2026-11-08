package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	goruntime "runtime"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Zane-SI/dotlink/internal/netcfg"
	"github.com/Zane-SI/dotlink/internal/proto"
	"github.com/Zane-SI/dotlink/internal/punch"
	"github.com/Zane-SI/dotlink/internal/relay"
	"github.com/Zane-SI/dotlink/internal/tunnel"
)

const (
	// DefaultUDPListen is the one port a Node needs to survive NAT for. The
	// same socket carries Relay traffic and, from #3 on, hole-punch probes.
	DefaultUDPListen = ":41641"
	// DefaultHeartbeat is how often the Node tells the Control Plane it is
	// alive when it is not otherwise polling.
	DefaultHeartbeat = 20 * time.Second
	// MTU is 1280: the IPv6 minimum, and small enough that a WireGuard packet
	// fits inside a 1500-byte path without fragmenting.
	MTU = 1280
)

// Daemon is one running Agent: a UDP socket, a Relay link over it, a TUN
// device and the WireGuard instance tying the two together.
type Daemon struct {
	State  State
	Logger *slog.Logger

	// Home overrides where the status snapshot is written. Empty means this
	// Node's DOTLINK_HOME.
	Home string

	UDPListen         string
	HeartbeatInterval time.Duration
	// HelloInterval is how often the Agent re-registers with the Relay. Short
	// values make recovery from a Relay restart fast at the cost of chatter;
	// the default is the 25s the spec asks for.
	HelloInterval time.Duration

	// MakeTUN and Configure are the only privileged steps. Tests replace them.
	MakeTUN   func(mtu int) (tun.Device, error)
	Configure func(ctx context.Context, cfg netcfg.Config) error
}

// home is where the status snapshot goes.
func (d *Daemon) home() string {
	if d.Home != "" {
		return d.Home
	}
	return mustHome()
}

func (d *Daemon) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

func (d *Daemon) makeTUN(mtu int) (tun.Device, error) {
	if d.MakeTUN != nil {
		return d.MakeTUN(mtu)
	}
	name := "utun"
	if goruntime.GOOS == "linux" {
		name = "dotlink"
	}
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN: %w (an Agent needs root for its TUN device)", err)
	}
	return dev, nil
}

func (d *Daemon) configure(ctx context.Context, cfg netcfg.Config) error {
	if d.Configure != nil {
		return d.Configure(ctx, cfg)
	}
	return netcfg.Configure(ctx, netcfg.ExecRunner{}, cfg)
}

// Run brings the tunnel up and keeps it up until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	log := d.logger()
	if d.State.NodeToken == "" {
		return errors.New("no Node identity: run `dotlink-agent join <link>` first")
	}
	priv, err := d.State.PrivateKey()
	if err != nil {
		return err
	}
	pub, err := d.State.PublicKey()
	if err != nil {
		return err
	}

	listen := d.UDPListen
	if listen == "" {
		listen = DefaultUDPListen
	}
	heartbeat := d.HeartbeatInterval
	if heartbeat == 0 {
		heartbeat = DefaultHeartbeat
	}

	ctrl := d.State.Control()

	// The first map decides the Relay, so it cannot be a long poll: hang here
	// and fail loudly instead of starting a tunnel that goes nowhere.
	pm, err := ctrl.Map(ctx, -1)
	if err != nil {
		return fmt.Errorf("fetch map: %w", err)
	}
	if pm == nil {
		return errors.New("fetch map: control plane had nothing to send")
	}
	relayAddr, secret, err := pickRelay(pm)
	if err != nil {
		return err
	}

	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}
	client, err := relay.NewClient(pc, relay.Config{
		Relay:         relayAddr,
		Pub:           pub,
		Secret:        secret,
		Logger:        log,
		HelloInterval: d.HelloInterval,
	})
	if err != nil {
		pc.Close()
		return err
	}
	defer client.Close()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	mgr := punch.New(punch.Config{
		Private:   priv,
		Public:    pub,
		Transport: probeSender{client},
		Logger:    log,
	})
	client.SetProbeHandler(func(from netip.AddrPort, frame []byte) {
		mgr.Handle(from, frame)
	})
	go mgr.Run(runCtx)
	if set, err := punchPeers(pm); err == nil {
		mgr.SetPeers(set)
	}

	self, err := parseSelf(pm)
	if err != nil {
		return err
	}
	tunDev, err := d.makeTUN(MTU)
	if err != nil {
		return err
	}
	// Until the WireGuard device exists, closing the TUN is our job; after
	// that the device owns it and closes it exactly once.
	ownsTUN := true
	defer func() {
		if ownsTUN {
			tunDev.Close()
		}
	}()
	iface, err := tunDev.Name()
	if err != nil {
		return fmt.Errorf("name TUN device: %w", err)
	}

	peers, err := peersFromMap(pm)
	if err != nil {
		return err
	}
	routes := subnetRoutes(pm)
	if err := d.configure(ctx, netcfg.Config{
		Name:    iface,
		IPv4:    self.IPv4,
		IPv4Net: overlayV4Net,
		IPv6:    self.IPv6,
		IPv6Net: overlayV6Net,
		MTU:     MTU,
		Routes:  routes,
	}); err != nil {
		return err
	}

	ownsTUN = false // New takes the device over, including closing it on error
	dev, err := tunnel.New(tunDev, tunnel.NewBind(client, mgr), tunnel.DeviceConfig{
		PrivateKey: priv,
		Peers:      peers,
		Logger:     device.NewLogger(device.LogLevelError, "dotlink"),
	})
	if err != nil {
		return err
	}
	defer dev.Close()

	live := &livePeers{}
	live.set(pm)
	state := &runtimeState{home: d.home(), rt: Runtime{
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC(),
		RelayUDP:  relayAddr.String(),
		Peers:     runtimePeers(pm, mgr),
	}}
	// A path change is worth a status refresh right away: punching is fast,
	// and a stale "Relayed" reads like a broken tunnel.
	mgr.SetOnPath(func([32]byte, punch.State) {
		if pm := live.get(); pm != nil && state != nil {
			state.setPeers(runtimePeers(pm, mgr))
			state.save(log)
		}
	})
	state.save(log)
	defer func() { _ = RemoveRuntimeIn(d.home()) }()

	log.Info("tunnel up",
		"node", d.State.Hostname,
		"ipv4", self.IPv4,
		"relay", relayAddr.String(),
		"peers", len(peers),
		"listen", pc.LocalAddr().String())

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		d.heartbeatLoop(runCtx, ctrl, client, mgr, live, state, heartbeat)
	}()
	go func() {
		defer wg.Done()
		d.mapLoop(runCtx, ctrl, dev, mgr, live, state, pm.Version)
	}()
	go func() {
		defer wg.Done()
		d.candidateLoop(runCtx, ctrl, pc, client, log)
	}()

	<-runCtx.Done()
	cancel()
	wg.Wait()
	log.Info("tunnel down")
	return nil
}

// heartbeatLoop is the Node's only unconditional sign of life. It also
// refreshes the Relay's registration flag in the status snapshot, because a
// Relay restart is exactly the thing a user wants to see.
func (d *Daemon) heartbeatLoop(ctx context.Context, ctrl *Control, client *relay.Client, mgr *punch.Manager, live *livePeers, st *runtimeState, every time.Duration) {
	log := d.logger()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := ctrl.Heartbeat(ctx); err != nil && ctx.Err() == nil {
				log.Warn("heartbeat", "err", err)
			}
			// Paths change between two heartbeats: punching is asynchronous.
			// Refreshing here keeps `status` honest without a second timer.
			changed := st.setRegistered(client.Registered())
			if pm := live.get(); pm != nil && st.setPeers(runtimePeers(pm, mgr)) {
				changed = true
			}
			if changed {
				st.save(log)
			}
		}
	}
}

// mapLoop follows the Peer Map for as long as the tunnel runs. Control Plane
// outages must not drop the tunnel, so errors back off instead of returning.
// candidateLoop publishes where this Agent can be reached. The lan address is
// free; the STUN answer costs one round trip to the Relay and is what makes a
// punch work across two networks instead of only inside one.
//
// It refreshes periodically because a public mapping changes when a NAT
// rebinds, and the control plane only bumps the map version when the list
// actually changes.
func (d *Daemon) candidateLoop(ctx context.Context, ctrl *Control, pc net.PacketConn, client *relay.Client, log *slog.Logger) {
	const refresh = 30 * time.Second
	t := time.NewTicker(refresh)
	defer t.Stop()
	for {
		cands := lanCandidates(pc)
		if mapped, err := client.DiscoverMapped(2 * time.Second); err == nil && mapped.IsValid() {
			cands = append(cands, proto.Candidate{Addr: mapped.String(), Kind: "stun"})
		} else if err != nil && ctx.Err() == nil {
			log.Debug("stun: no mapping", "err", err)
		}
		if len(cands) > 0 {
			if err := ctrl.SetCandidates(ctx, cands); err != nil && ctx.Err() == nil {
				log.Warn("publish candidates", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (d *Daemon) mapLoop(ctx context.Context, ctrl *Control, dev *tunnel.Device, mgr *punch.Manager, live *livePeers, st *runtimeState, version int64) {
	log := d.logger()
	backoff := time.Second
	for ctx.Err() == nil {
		pm, err := ctrl.Map(ctx, version)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("map", "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		if pm == nil {
			continue
		}
		version = pm.Version
		peers, err := peersFromMap(pm)
		if err != nil {
			log.Warn("map: bad peer", "err", err)
			continue
		}
		if err := dev.Apply(peers); err != nil {
			log.Warn("apply peers", "err", err)
			continue
		}
		live.set(pm)
		if set, err := punchPeers(pm); err == nil {
			mgr.SetPeers(set)
		} else {
			log.Warn("map: bad candidate set", "err", err)
		}
		if st.setPeers(runtimePeers(pm, mgr)) {
			st.save(log)
		}
	}
}

type runtimeState struct {
	home string
	mu   sync.Mutex
	rt   Runtime
}

func (s *runtimeState) save(log *slog.Logger) {
	s.mu.Lock()
	snapshot := s.rt
	snapshot.Peers = append([]RuntimePeer(nil), s.rt.Peers...)
	s.mu.Unlock()
	if err := SaveRuntimeIn(s.home, snapshot); err != nil {
		log.Warn("write runtime file", "err", err)
	}
}

func (s *runtimeState) setRegistered(v bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rt.Registered == v {
		return false
	}
	s.rt.Registered = v
	return true
}

func (s *runtimeState) setPeers(peers []RuntimePeer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sameRuntimePeers(s.rt.Peers, peers) {
		return false
	}
	s.rt.Peers = peers
	return true
}

func sameRuntimePeers(a, b []RuntimePeer) bool {
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

var (
	overlayV4Net = netip.MustParsePrefix("100.64.0.0/10")
	overlayV6Net = netip.MustParsePrefix("fd00::/64")
)

func pickRelay(pm *proto.PeerMap) (netip.AddrPort, []byte, error) {
	for _, r := range pm.Relays {
		if r.UDP == "" {
			continue
		}
		addr, err := netip.ParseAddrPort(r.UDP)
		if err != nil {
			return netip.AddrPort{}, nil, fmt.Errorf("relay %s: %q is not ip:port", r.ID, r.UDP)
		}
		if r.Secret == "" {
			return netip.AddrPort{}, nil, fmt.Errorf("relay %s: map has no secret", r.ID)
		}
		return addr, []byte(r.Secret), nil
	}
	return netip.AddrPort{}, nil, errors.New("map lists no Relay: the Control Plane needs --relay-udp")
}

// overlayAddrs is this Node's own addresses, as the kernel needs them.
type overlayAddrs struct {
	IPv4 netip.Addr
	IPv6 netip.Addr
}

func parseSelf(pm *proto.PeerMap) (overlayAddrs, error) {
	v4, err := netip.ParseAddr(pm.Self.IPv4)
	if err != nil || !v4.Is4() {
		return overlayAddrs{}, fmt.Errorf("map: self IPv4 %q is not an address", pm.Self.IPv4)
	}
	out := overlayAddrs{IPv4: v4}
	if v6, err := netip.ParseAddr(pm.Self.IPv6); err == nil && v6.Is6() {
		out.IPv6 = v6
	}
	return out, nil
}

// peersFromMap turns the Peer Map into WireGuard peers: each Node is reachable
// at exactly its overlay addresses, plus whatever it routes for.
func peersFromMap(pm *proto.PeerMap) ([]tunnel.Peer, error) {
	out := make([]tunnel.Peer, 0, len(pm.Peers))
	for _, p := range pm.Peers {
		pub, err := decodeKey(p.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", p.Hostname, err)
		}
		var prefixes []netip.Prefix
		if addr, err := netip.ParseAddr(p.IPv4); err == nil && addr.Is4() {
			prefixes = append(prefixes, netip.PrefixFrom(addr, 32))
		}
		if addr, err := netip.ParseAddr(p.IPv6); err == nil && addr.Is6() {
			prefixes = append(prefixes, netip.PrefixFrom(addr, 128))
		}
		for _, raw := range p.SubnetRoutes {
			pr, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("peer %s: subnet route %q is not a prefix", p.Hostname, raw)
			}
			prefixes = append(prefixes, pr)
		}
		out = append(out, tunnel.Peer{Pub: pub, Prefixes: prefixes})
	}
	return out, nil
}

// subnetRoutes is every LAN a peer routes for. Without a route the packets
// would leave through the default gateway instead of the tunnel.
func subnetRoutes(pm *proto.PeerMap) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range pm.Peers {
		for _, raw := range p.SubnetRoutes {
			if pr, err := netip.ParsePrefix(raw); err == nil {
				out = append(out, pr)
			}
		}
	}
	return out
}

func runtimePeers(pm *proto.PeerMap, mgr *punch.Manager) []RuntimePeer {
	out := make([]RuntimePeer, 0, len(pm.Peers))
	for _, p := range pm.Peers {
		rp := RuntimePeer{Hostname: p.Hostname, IPv4: p.IPv4, Path: string(punch.StateRelayed)}
		if key, err := decodeKey(p.Pubkey); err == nil {
			state, rtt := mgr.State(key)
			rp.Path = string(state)
			if state == punch.StateDirect {
				rp.RTTms = rtt.Milliseconds()
			}
		}
		out = append(out, rp)
	}
	return out
}

// punchPeers turns the Peer Map into the probing table.
func punchPeers(pm *proto.PeerMap) ([]punch.Peer, error) {
	out := make([]punch.Peer, 0, len(pm.Peers))
	for _, p := range pm.Peers {
		key, err := decodeKey(p.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", p.Hostname, err)
		}
		cands := make([]netip.AddrPort, 0, len(p.Candidates))
		for _, c := range p.Candidates {
			ap, err := netip.ParseAddrPort(c.Addr)
			if err != nil {
				continue // a bad candidate costs a probe, not the tunnel
			}
			cands = append(cands, ap)
		}
		out = append(out, punch.Peer{Key: key, Candidates: cands})
	}
	return out, nil
}

// probeSender puts probes on the same socket the Relay link uses, so the
// mapping a punch creates is the mapping WireGuard sends from.
type probeSender struct {
	client *relay.Client
}

func (p probeSender) SendProbe(addr netip.AddrPort, frame []byte) error {
	return p.client.SendToAddr(addr, frame)
}

// livePeers holds the latest Peer Map for the heartbeat's path refresh.
type livePeers struct {
	mu sync.Mutex
	pm *proto.PeerMap
}

func (l *livePeers) set(pm *proto.PeerMap) {
	l.mu.Lock()
	l.pm = pm
	l.mu.Unlock()
}

func (l *livePeers) get() *proto.PeerMap {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pm
}

// lanCandidates publishes the address this Node is reachable at on its own
// LAN. #3 adds the STUN-derived public mapping; until then a peer on the same
// wire can already talk to us directly once punching lands.
func lanCandidates(pc net.PacketConn) []proto.Candidate {
	addr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	ip := addr.AddrPort().Addr()
	if ip.IsUnspecified() {
		return nil
	}
	return []proto.Candidate{{Addr: addr.AddrPort().String(), Kind: "lan"}}
}
