package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	goruntime "runtime"
	"sort"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Zane-SI/dotlink/internal/ctlapi"
	"github.com/Zane-SI/dotlink/internal/derp"
	"github.com/Zane-SI/dotlink/internal/link"
	"github.com/Zane-SI/dotlink/internal/magicdns"
	"github.com/Zane-SI/dotlink/internal/netcfg"
	"github.com/Zane-SI/dotlink/internal/netshare"
	"github.com/Zane-SI/dotlink/internal/proto"
	"github.com/Zane-SI/dotlink/internal/punch"
	"github.com/Zane-SI/dotlink/internal/relay"
	"github.com/Zane-SI/dotlink/internal/subnet"
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

	// DERPAddr overrides the DERP endpoint from the Peer Map. Empty means use
	// relays[0].derp, which is what a deployment wants.
	DERPAddr string
	// DERPTLS configures certificate verification for DERP. Nil means system
	// roots, which is right for a real certificate and wrong for a test.
	DERPTLS *tls.Config
	// LinkFailAfter is how long UDP may stay unregistered before DERP takes
	// over. Zero means link.DefaultFailAfter.
	LinkFailAfter time.Duration
	// NoPunch keeps the tunnel on the Relay. Punching is not always possible
	// (some carriers never let a mapping through) and skipping it is cheaper
	// than watching five rounds fail every minute.
	NoPunch bool

	// AdvertiseRoutes are the LANs this Node forwards for. Empty means this
	// Node is not a Gateway.
	AdvertiseRoutes []netip.Prefix

	// EnableNetshare turns on forwarding and NAT for AdvertiseRoutes. Nil
	// means the platform implementation; tests replace it, because pfctl is
	// not something a test run should touch on the developer's machine.
	EnableNetshare func(ctx context.Context, cfg netshare.Config) (func(), error)

	// SyncRoutes installs and removes the routes other Nodes' LANs need. Nil
	// means the platform implementation (netcfg + route(8)); tests replace it
	// with a recorder, because a test run must not edit the host's table.
	SyncRoutes func(ctx context.Context, iface string, add, remove []netip.Prefix) error

	// Runner runs the route commands SyncRoutes issues. Nil means
	// netcfg.ExecRunner{}; tests set it to a recorder that captures the
	// commands without touching the host's routing table.
	Runner netcfg.Runner

	// DNSListen overrides the address MagicDNS binds. Empty means the Node's
	// own Overlay IPv4: that is the point of listening there — a query for
	// mac-mini.dotlink never leaves the machine that asked.
	DNSListen string
	// DNSPort overrides :53, which only root can bind.
	DNSPort int
	// ConfigureResolver installs the OS's split-DNS rule. Nil means the
	// platform default (netcfg.WriteResolver).
	ConfigureResolver func(zone string, addr netip.Addr) (func(), error)

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

// state0 adapts livePeers to the lookup magicdns wants.
func state0(live *livePeers) func() map[string]magicdns.Record {
	return func() map[string]magicdns.Record {
		pm := live.get()
		if pm == nil {
			return nil
		}
		out := make(map[string]magicdns.Record, len(pm.Peers)+1)
		if self, err := parseSelf(pm); err == nil {
			out[magicdns.Label(pm.Self.Hostname)] = magicdns.Record{IPv4: self.IPv4, IPv6: self.IPv6}
		}
		for _, p := range pm.Peers {
			v4, _ := netip.ParseAddr(p.IPv4)
			v6, _ := netip.ParseAddr(p.IPv6)
			name := p.DNSName
			if name == "" {
				name = magicdns.Label(p.Hostname)
			}
			out[name] = magicdns.Record{IPv4: v4, IPv6: v6}
		}
		return out
	}
}

// startMagicDNS serves the zone and installs the OS rule, returning a cleanup
// that removes the rule before the address it points at goes away.
func (d *Daemon) startMagicDNS(ctx context.Context, zone string, self netip.Addr, lookup func() map[string]magicdns.Record, log *slog.Logger) func() {
	if zone == "" || !self.IsValid() {
		return func() {}
	}
	dns := &magicdns.Server{Zone: zone, Addr: self, Local: d.DNSListen, Port: d.DNSPort, Lookup: lookup, Log: log}
	go func() {
		if err := dns.ListenAndServe(ctx); err != nil {
			log.Warn("magicdns stopped", "err", err)
		}
	}()

	configure := d.ConfigureResolver
	if configure == nil {
		configure = netcfg.WriteResolver
	}
	remove, err := configure(zone, self)
	if err != nil {
		// The tunnel works without names; failing the session over DNS would
		// take the network down to protect a convenience.
		log.Warn("magicdns: could not install the resolver rule", "zone", zone, "err", err)
		return func() { _ = dns.Close() }
	}
	log.Info("magicdns installed", "zone", zone, "addr", self.String())
	return func() {
		remove()
		_ = dns.Close()
	}
}

// permanentError marks a failure that retrying cannot fix: a rejected
// advertisement, a missing LAN, a flag that will parse the same way every two
// seconds. The Supervisor uses it to stay down until the user reconnects.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// permanent wraps err without changing its message, so operators still see the
// Control Plane's own explanation.
func permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

func isPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

// rejectedStatus says whether the Control Plane's answer will still be wrong
// after a retry. 408 and 429 are explicitly retryable: the request was not
// understood to be invalid, the server was busy or the client timed out.
func rejectedStatus(code int) bool {
	switch code {
	case 400, 401, 403, 404, 405, 409, 422:
		return true
	}
	return false
}

// normalizeRoutes turns --advertise-routes into the one shape the rest of the
// daemon uses: masked, deduped, sorted, and held to the same limits the
// Control Plane enforces. It runs before any privileged step, so a bad flag
// fails before a TUN or a pf anchor exists to clean up.
func normalizeRoutes(in []netip.Prefix) ([]netip.Prefix, error) {
	return subnet.Normalize(in)
}

// advertiseRoutes publishes the advertisement, empty included: an Agent that
// restarts without --advertise-routes must withdraw the claim it made last
// time, or peers keep sending LAN traffic to a Gateway that no longer serves
// it. It fails loudly: a Gateway whose advertisement was rejected must not sit
// there looking healthy while peers see nothing.
func (d *Daemon) advertiseRoutes(ctx context.Context, ctrl *Control, routes []netip.Prefix, log *slog.Logger) error {
	if err := ctrl.SetRoutes(ctx, routeStrings(routes)); err != nil {
		var status *ctlapi.StatusError
		if errors.As(err, &status) {
			// An older Control Plane has no /v1/routes. An Agent with nothing
			// to advertise has nothing to withdraw either, so this is not a
			// reason to stop a working tunnel; a Gateway that does have a
			// claim to make still fails loudly below.
			if status.Status == 404 && len(routes) == 0 {
				log.Warn("control plane has no subnet-route endpoint; nothing to withdraw")
				return nil
			}
			if rejectedStatus(status.Status) {
				// A rejected claim must not leave the old one standing: peers would
				// keep routing the old LANs here even though this Agent is dying.
				// Only a rejection is permanent though — a 5xx, 408 or 429 is
				// transient, and withdrawing would drop a claim that is still valid.
				d.withdrawRoutes(ctrl, log)
				return permanent(fmt.Errorf("advertise routes: %w", err))
			}
		}
		return fmt.Errorf("advertise routes: %w", err)
	}
	if len(routes) > 0 {
		log.Info("advertised subnet routes", "routes", routeStrings(routes))
	}
	return nil
}

// withdrawRoutes releases this Node's claim on the way out. It gets its own
// timeout instead of the session's context: shutdown must not hang on a
// Control Plane that is already going away.
func (d *Daemon) withdrawRoutes(ctrl *Control, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ctrl.SetRoutes(ctx, nil); err != nil {
		log.Warn("withdraw subnet routes", "err", err)
	}
}

// syncRoutes applies a route delta with the production runner unless a test
// replaced it.
func (d *Daemon) syncRoutes(ctx context.Context, iface string, add, remove []netip.Prefix) error {
	if d.SyncRoutes != nil {
		return d.SyncRoutes(ctx, iface, add, remove)
	}
	r := d.Runner
	if r == nil {
		r = netcfg.ExecRunner{}
	}
	var errs []error
	for _, pr := range add {
		if err := netcfg.AddRoute(ctx, r, iface, pr); err != nil {
			errs = append(errs, err)
		}
	}
	for _, pr := range remove {
		if err := netcfg.DeleteRoute(ctx, r, iface, pr); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// reconcileRoutes installs the difference between what is on the TUN and what
// the map now wants, returning the installed set. On failure the old set is
// returned so the next poll retries the same delta; a route that could not be
// installed must not be forgotten, or it would never be retried.
func (d *Daemon) reconcileRoutes(ctx context.Context, iface string, installed, desired []netip.Prefix, log *slog.Logger) []netip.Prefix {
	add, remove := routeDelta(installed, desired)
	if len(add) == 0 && len(remove) == 0 {
		return installed
	}
	if err := d.syncRoutes(ctx, iface, add, remove); err != nil {
		log.Warn("sync peer routes", "add", routeStrings(add), "remove", routeStrings(remove), "err", err)
		return installed
	}
	return desired
}

// routeDelta is the set difference between what is installed and what the map
// wants. Pure, so the interesting cases — a Gateway appearing, a Gateway
// leaving, a failed install being retried — need no network to test.
func routeDelta(installed, desired []netip.Prefix) (add, remove []netip.Prefix) {
	have := make(map[netip.Prefix]bool, len(installed))
	for _, pr := range installed {
		have[pr.Masked()] = true
	}
	want := make(map[netip.Prefix]bool, len(desired))
	for _, pr := range desired {
		pr = pr.Masked()
		want[pr] = true
		if !have[pr] {
			add = append(add, pr)
		}
	}
	for _, pr := range installed {
		pr = pr.Masked()
		if !want[pr] {
			remove = append(remove, pr)
		}
	}
	sortPrefixes(add)
	sortPrefixes(remove)
	return add, remove
}

// sortPrefixes gives routes one stable order, so logs and deltas do not
// shuffle between two polls of the same map.
func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].String() < ps[j].String() })
}

// routeStrings is the wire form: canonical, sorted, one prefix per entry.
func routeStrings(routes []netip.Prefix) []string {
	out := make([]string, 0, len(routes))
	for _, pr := range routes {
		out = append(out, pr.Masked().String())
	}
	sort.Strings(out)
	return out
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

	// Validate and canonicalize before anything privileged exists.
	advertised, err := normalizeRoutes(d.AdvertiseRoutes)
	if err != nil {
		// The same flags produce the same error until someone edits them.
		return permanent(err)
	}

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

	// DERP is optional: a network where UDP works never needs it, and an
	// Agent with no DERP configured must still come up.
	derpAddr := d.DERPAddr
	if derpAddr == "" {
		derpAddr = derpFromMap(pm)
	}
	var derpClient *derp.Client
	if derpAddr != "" {
		dc, err := dialDERP(runCtx, derpAddr, pub, d.DERPTLS, log)
		if err != nil {
			log.Warn("derp unavailable, continuing on udp only", "addr", derpAddr, "err", err)
		} else {
			derpClient = dc
		}
	}
	// A typed nil in an interface is not nil: hand over an untyped nil when
	// there is no DERP client, or the pump would be started on nothing.
	var derpBackend link.DERPBackend
	if derpClient != nil {
		derpBackend = derpClient
	}
	lnk := link.New(client, derpBackend, log)
	if d.LinkFailAfter > 0 {
		lnk.FailAfter = d.LinkFailAfter
	}
	go lnk.Run(runCtx)
	if derpAddr != "" {
		go maintainDERP(runCtx, derpAddr, pub, d.DERPTLS, lnk, log)
	}

	mgr := punch.New(punch.Config{
		Private:   priv,
		Public:    pub,
		Transport: probeSender{lnk},
		Logger:    log,
	})
	client.SetProbeHandler(func(from netip.AddrPort, frame []byte) {
		mgr.Handle(from, frame)
	})
	go mgr.Run(runCtx)
	if set, err := punchPeers(pm); err == nil && !d.NoPunch {
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
	peerRoutes := subnetRoutes(pm)
	if err := d.configure(ctx, netcfg.Config{
		Name:    iface,
		IPv4:    self.IPv4,
		IPv4Net: subnet.OverlayV4,
		IPv6:    self.IPv6,
		IPv6Net: subnet.OverlayV6,
		MTU:     MTU,
		Routes:  peerRoutes,
	}); err != nil {
		return err
	}

	// The LAN has to work before the Control Plane tells peers to use it: a
	// claim for a Gateway that cannot forward black-holes every peer's traffic
	// to that LAN. Netshare therefore comes before the advertisement, never
	// the other way round.
	if len(advertised) > 0 {
		enable := d.EnableNetshare
		if enable == nil {
			enable = func(ctx context.Context, cfg netshare.Config) (func(), error) {
				return netshare.Enable(ctx, netcfg.ExecRunner{}, cfg)
			}
		}
		stopShare, err := enable(ctx, netshare.Config{
			TUN:       iface,
			Routes:    advertised,
			TokenPath: netshare.DefaultTokenPath,
		})
		if err != nil {
			// Do not leave a stale claim behind if this machine used to be a
			// Gateway for these LANs.
			d.withdrawRoutes(ctrl, log)
			// Privileged setup failed for a reason (no route to the LAN, pf
			// refused the anchor), and re-running it every two seconds only
			// re-runs the same failure.
			return permanent(fmt.Errorf("subnet router: %w", err))
		}
		defer stopShare()
		log.Info("subnet router enabled", "routes", routeStrings(advertised), "tun", iface)
	}

	if err := d.advertiseRoutes(ctx, ctrl, advertised, log); err != nil {
		return err
	}
	if len(advertised) > 0 {
		// A deliberate stop is the normal end of a session: tell the Control
		// Plane, so a restart without the flag cannot keep a dead claim alive.
		defer d.withdrawRoutes(ctrl, log)
	}

	ownsTUN = false // New takes the device over, including closing it on error
	dev, err := tunnel.New(tunDev, tunnel.NewBind(lnk, mgr), tunnel.DeviceConfig{
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

	// MagicDNS. The listener is on our own Overlay address, which the kernel
	// treats as local: queries are delivered without ever reaching the TUN,
	// so they cannot leak to a peer or to the system resolver.
	stopDNS := d.startMagicDNS(runCtx, pm.Network.Domain, self.IPv4, state0(live), log)
	defer stopDNS()
	state := &runtimeState{home: d.home(), rt: Runtime{
		PID:             os.Getpid(),
		StartedAt:       time.Now().UTC(),
		Hostname:        d.State.Hostname,
		IPv4:            self.IPv4.String(),
		IPv6:            self.IPv6.String(),
		Network:         pm.Network.Name,
		RelayUDP:        relayAddr.String(),
		RelayMode:       string(lnk.Mode()),
		AdvertiseRoutes: routeStrings(advertised),
		Peers:           runtimePeers(pm, mgr),
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
		d.heartbeatLoop(runCtx, ctrl, client, lnk, mgr, live, state, heartbeat)
	}()
	go func() {
		defer wg.Done()
		d.mapLoop(runCtx, ctrl, dev, mgr, live, state, pm.Version, iface, peerRoutes)
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
func (d *Daemon) heartbeatLoop(ctx context.Context, ctrl *Control, client *relay.Client, lnk *link.Link, mgr *punch.Manager, live *livePeers, st *runtimeState, every time.Duration) {
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
			if st.setMode(string(lnk.Mode())) {
				changed = true
			}
			if pm := live.get(); pm != nil && st.setPeers(runtimePeers(pm, mgr)) {
				changed = true
			}
			if changed {
				st.save(log)
			}
		}
	}
}

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

// waitForRetry sleeps for d, reporting false when the context ended first.
// Callers return on false so a shutdown does not have to wait out the backoff.
func waitForRetry(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// mapLoop follows the Peer Map for as long as the tunnel runs. Control Plane
// outages must not drop the tunnel, so errors back off instead of returning.
// Route changes are reconciled here too: a Gateway may appear or leave long
// after the TUN was configured.
func (d *Daemon) mapLoop(ctx context.Context, ctrl *Control, dev *tunnel.Device, mgr *punch.Manager, live *livePeers, st *runtimeState, version int64, iface string, installed []netip.Prefix) {
	log := d.logger()
	backoff := time.Second
	desired := installed
	for ctx.Err() == nil {
		pm, err := ctrl.Map(ctx, version)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("map", "err", err, "retry_in", backoff)
			if !waitForRetry(ctx, backoff) {
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		if pm == nil {
			// Nothing new, but a route install may have failed last time: the
			// retry must not wait for a map change that may never come.
			installed = d.reconcileRoutes(ctx, iface, installed, desired, log)
			continue
		}
		desired = subnetRoutes(pm)
		// Peers first, routes second. Installing a kernel route before the
		// peer's allowed IPs exist black-holes that LAN: the packet leaves
		// through the TUN and WireGuard has nowhere to send it.
		peers, err := peersFromMap(pm)
		if err != nil {
			log.Warn("map: bad peer", "err", err, "retry_in", backoff)
			if !waitForRetry(ctx, backoff) {
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		if err := dev.Apply(peers); err != nil {
			log.Warn("apply peers", "err", err, "retry_in", backoff)
			if !waitForRetry(ctx, backoff) {
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		// Only a successful Apply may advance the version. Otherwise the next
		// long poll asks for the same map and can retry the peers it missed;
		// advancing first would make the Control Plane answer 204 forever.
		//
		// That is why the failure branches above pause before retrying: with
		// version unchanged the Control Plane answers the same map at once
		// when `since < currentVersion`, so a persistent bad map (invalid
		// pubkey, bad subnet_routes) or a persistent Apply failure would spin
		// at full speed. The pause keeps the retry loop from becoming a hot
		// loop, and the backoff resets only here, once the map is really
		// installed.
		backoff = time.Second
		version = pm.Version
		installed = d.reconcileRoutes(ctx, iface, installed, desired, log)
		live.set(pm)
		if set, err := punchPeers(pm); err == nil && !d.NoPunch {
			mgr.SetPeers(set)
		} else if err != nil {
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

func (s *runtimeState) setMode(m string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rt.RelayMode == m {
		return false
	}
	s.rt.RelayMode = m
	return true
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

// subnetRoutes is every LAN a peer routes for: masked, deduped, sorted, so it
// can be compared against what is installed without spurious deltas. Without a
// route the packets would leave through the default gateway instead of the
// tunnel.
func subnetRoutes(pm *proto.PeerMap) []netip.Prefix {
	var out []netip.Prefix
	seen := make(map[netip.Prefix]bool)
	for _, p := range pm.Peers {
		for _, raw := range p.SubnetRoutes {
			pr, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			pr = pr.Masked()
			if seen[pr] {
				continue
			}
			seen[pr] = true
			out = append(out, pr)
		}
	}
	sortPrefixes(out)
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
	client interface {
		SendToAddr(addr netip.AddrPort, payload []byte) error
	}
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

// derpFromMap returns the DERP endpoint the Control Plane advertised, if any.
// Only the first Relay ever has one: v1 runs a single Relay.
func derpFromMap(pm *proto.PeerMap) string {
	for _, r := range pm.Relays {
		if r.DERP != "" {
			return r.DERP
		}
	}
	return ""
}

// dialDERP opens the TLS fallback. A failure is not fatal: the Agent keeps the
// UDP Relay and tries again from maintainDERP.
func dialDERP(ctx context.Context, addr string, pub [32]byte, tlsCfg *tls.Config, log *slog.Logger) (*derp.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return derp.Dial(ctx, derp.Config{Addr: addr, TLS: tlsCfg, Key: pub, Logger: log})
}

// maintainDERP reconnects the fallback whenever it is not up. The DERP server
// may restart, the path may be re-established after a sleep; none of that
// should need an Agent restart.
func maintainDERP(ctx context.Context, addr string, pub [32]byte, tlsCfg *tls.Config, lnk *link.Link, log *slog.Logger) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if lnk.DERPUp() {
				continue
			}
			c, err := dialDERP(ctx, addr, pub, tlsCfg, log)
			if err != nil {
				log.Debug("derp still unreachable", "addr", addr, "err", err)
				continue
			}
			lnk.SetDERP(c)
			log.Info("derp connected", "addr", addr)
		}
	}
}
