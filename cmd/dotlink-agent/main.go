// Command dotlink-agent is the per-Node side: it enrolls, brings the tunnel
// up, and answers questions about what it can reach.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Zane-SI/dotlink/internal/agent"
	"github.com/Zane-SI/dotlink/internal/ipc"
	"github.com/Zane-SI/dotlink/internal/proto"
)

// version is stamped at build time with -ldflags -X main.version=…
var version = "dev"

// routesFlag accepts --advertise-routes a,b and --advertise-routes a
// --advertise-routes b, because both spellings are what people type.
type routesFlag []netip.Prefix

func (r *routesFlag) String() string {
	out := make([]string, 0, len(*r))
	for _, pr := range *r {
		out = append(out, pr.String())
	}
	return strings.Join(out, ",")
}

func (r *routesFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pr, err := netip.ParsePrefix(part)
		if err != nil {
			return fmt.Errorf("%q is not a CIDR prefix", part)
		}
		*r = append(*r, pr.Masked())
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "join":
		err = runJoin(os.Args[2:])
	case "nodes":
		err = runNodes(os.Args[2:])
	case "up":
		err = runUp(os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(version)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "dotlink-agent: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dotlink-agent — join a Dotlink Network

  dotlink-agent join <dotlink://enroll?...>   redeem an invite
  dotlink-agent up   [flags]                  bring the tunnel up (needs root)
  dotlink-agent nodes [flags]                 list the Nodes you can reach
  dotlink-agent status                        show this Node's identity and tunnel
  dotlink-agent version                       print the build
  dotlink-agent version                       print the build

Run "dotlink-agent <command> -h" for flags.
`)
}

func runJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	hostname := fs.String("hostname", "", "name other Nodes see (defaults to this machine's hostname)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: dotlink-agent join <dotlink://enroll?...> [--hostname name]")
	}
	// The link may come before or after the flags: the flag package stops at
	// the first non-flag argument, so parse the remainder too.
	raw := fs.Arg(0)
	if err := fs.Parse(fs.Args()[1:]); err != nil {
		return err
	}

	link, err := agent.ParseEnrollLink(raw)
	if err != nil {
		return err
	}
	name := *hostname
	if name == "" {
		name = defaultHostname()
	}

	st, err := agent.Enroll(context.Background(), link, name, runtime.GOOS)
	if err != nil {
		return err
	}
	if err := agent.SaveState(st); err != nil {
		return err
	}

	path, _ := agent.StatePath()
	fmt.Printf("joined network %q as %s (%s)\n", st.Network.Name, st.NodeID, st.Hostname)
	fmt.Printf("overlay: %s / %s\n", st.IPv4, st.IPv6)
	fmt.Printf("state:   %s\n", path)

	pm, err := st.Control().Map(context.Background(), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read the Peer Map yet: %v\n", err)
		return nil
	}
	printNodes(pm)
	return nil
}

func runNodes(args []string) error {
	fs := flag.NewFlagSet("nodes", flag.ExitOnError)
	watch := fs.Bool("watch", false, "keep long-polling and print the map whenever it changes")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := agent.LoadState()
	if err != nil {
		return err
	}
	ctl := st.Control()

	if !*watch {
		pm, err := ctl.Map(context.Background(), 0)
		if err != nil {
			return err
		}
		printNodes(pm)
		return nil
	}

	since := st.Version
	for {
		pm, err := ctl.Map(context.Background(), since)
		if err != nil {
			return err
		}
		if pm == nil {
			continue // long poll timed out with nothing new
		}
		since = pm.Version
		printNodes(pm)
		fmt.Println()
	}
}

type upOptions struct {
	listen     string
	derpAddr   string
	socket     string
	adminToken string
	relayOnly  bool
	routes     []netip.Prefix
}

// parseUpFlags keeps the flags in one place so a test can prove
// --advertise-routes reaches the Daemon instead of only testing the flag type.
func parseUpFlags(args []string) (upOptions, error) {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	listen := fs.String("listen", agent.DefaultUDPListen, "UDP listen address; the same socket carries Relay traffic and hole punching")
	derpAddr := fs.String("derp", "", "DERP endpoint to use instead of the one in the Peer Map")
	relayOnly := fs.Bool("relay-only", false, "skip hole punching and stay on the Relay")
	socket := fs.String("socket", ipc.DefaultSocket, "Unix socket the menu bar app talks to")
	adminToken := fs.String("admin-token", "", "Control Plane admin token; needed only to sign invites (env DOTLINK_ADMIN_TOKEN)")
	var routes routesFlag
	fs.Var(&routes, "advertise-routes", "LAN prefixes to forward for, comma separated (e.g. 192.168.1.0/24)")
	if err := fs.Parse(args); err != nil {
		return upOptions{}, err
	}
	return upOptions{
		listen:     *listen,
		derpAddr:   *derpAddr,
		socket:     *socket,
		adminToken: *adminToken,
		relayOnly:  *relayOnly,
		routes:     routes,
	}, nil
}

func upDaemon(opts upOptions, st agent.State, log *slog.Logger) *agent.Daemon {
	return &agent.Daemon{
		State:           st,
		UDPListen:       opts.listen,
		DERPAddr:        opts.derpAddr,
		NoPunch:         opts.relayOnly,
		AdvertiseRoutes: opts.routes,
		Logger:          log,
	}
}

func runUp(args []string) error {
	opts, err := parseUpFlags(args)
	if err != nil {
		return err
	}
	if len(opts.routes) == 0 {
		// launchd has no shell to put --advertise-routes on the command line;
		// the config file is how a packaged Gateway advertises its LAN.
		opts.routes, err = agent.LoadAdvertiseRoutes()
		if err != nil {
			return err
		}
	}
	token := opts.adminToken
	if token == "" {
		token = os.Getenv("DOTLINK_ADMIN_TOKEN")
	}

	st, err := agent.LoadState()
	if err != nil {
		return err
	}

	// A Ctrl-C must take the TUN and its routes down with it; the daemon
	// cleans up on context cancellation.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	d := upDaemon(opts, st, log)

	// The supervisor owns the tunnel; the socket owns the supervisor. A menu
	// bar disconnect must not kill the process, or KeepAlive would bring the
	// tunnel straight back.
	sup := &agent.Supervisor{Run: d.Run, Logger: log}
	go sup.Serve(ctx)

	local := &agent.LocalControl{Supervisor: sup, State: st, AdminToken: token, Logger: log}
	srv := &ipc.Server{Path: opts.socket, Provider: local, Logger: log}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe(ctx) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		// The tunnel works without the socket; only the Client goes blind.
		if err != nil {
			log.Error("agent socket stopped", "err", err)
		}
		sup.Stop()
		return err
	}
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	socket := fs.String("socket", ipc.DefaultSocket, "Unix socket the Agent listens on")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := agent.LoadState()
	if err != nil {
		return err
	}
	path, _ := agent.StatePath()
	fmt.Printf("node:    %s (%s)\n", st.NodeID, st.Hostname)
	fmt.Printf("server:  %s\n", st.Server)
	fmt.Printf("overlay: %s / %s\n", st.IPv4, st.IPv6)
	fmt.Printf("network: %s (MagicDNS .%s)\n", st.Network.Name, st.Network.Domain)
	fmt.Printf("state:   %s\n", path)

	// The socket is authoritative when the daemon is up: it knows whether the
	// tunnel was disconnected without the process exiting.
	if live, err := ipc.NewClient(*socket).Status(context.Background()); err == nil {
		printLiveStatus(live)
		return nil
	}
	rt, err := agent.LoadRuntime()
	switch {
	case err != nil:
		fmt.Println("agent:   not running (start it with `sudo dotlink-agent up`)")
		return nil
	default:
		registered := "not registered"
		if rt.Registered {
			registered = "registered"
		}
		fmt.Printf("agent:   running (pid %d, up %s, relay %s, %s)\n",
			rt.PID, time.Since(rt.StartedAt).Round(time.Second), rt.RelayUDP, registered)
	}
	if len(rt.Peers) == 0 {
		fmt.Println("peers:   none yet")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOSTNAME\tIPV4\tPATH")
	for _, p := range rt.Peers {
		fmt.Fprintf(w, "%s\t%s\t%s\n", p.Hostname, p.IPv4, p.Path)
	}
	w.Flush()
	return nil
}

func printNodes(pm *proto.PeerMap) {
	if pm == nil {
		fmt.Println("no map yet")
		return
	}
	fmt.Printf("version %d — self %s (%s)\n", pm.Version, pm.Self.Hostname, pm.Self.IPv4)
	if len(pm.Peers) == 0 {
		fmt.Println("no other Nodes yet: invite someone with `dotlink-server invite`")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOSTNAME\tIPV4\tIPV6\tONLINE\tLAST SEEN\tROUTES")
	for _, p := range pm.Peers {
		online := "no"
		if p.Online {
			online = "yes"
		}
		routes := "-"
		if len(p.SubnetRoutes) > 0 {
			routes = strings.Join(p.SubnetRoutes, ",")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			p.Hostname, p.IPv4, p.IPv6, online, p.LastSeen.Local().Format(time.RFC3339), routes)
	}
	w.Flush()
}

func defaultHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "dotlink-node"
}

// printLiveStatus renders what the daemon reports over its socket.
func printLiveStatus(st ipc.Status) {
	state := "running"
	if !st.Running {
		state = "disconnected"
	}
	relay := st.RelayUDP
	if st.RelayMode != "" {
		relay = fmt.Sprintf("%s (%s)", st.RelayUDP, st.RelayMode)
	}
	fmt.Printf("agent:   %s (pid %d, relay %s)\n", state, st.PID, relay)
	fmt.Printf("overlay: %s / %s\n", st.IPv4, st.IPv6)
	routes := "none"
	if len(st.AdvertiseRoutes) > 0 {
		routes = strings.Join(st.AdvertiseRoutes, ", ")
	}
	fmt.Printf("routes:  %s\n", routes)
	if st.Error != "" {
		fmt.Printf("error:   %s\n", st.Error)
	}
	if len(st.Peers) == 0 {
		fmt.Println("peers:   none yet")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOSTNAME\tIPV4\tPATH\tRTT")
	for _, p := range st.Peers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", p.Hostname, p.IPv4, p.Path, p.RTTms)
	}
	w.Flush()
}
