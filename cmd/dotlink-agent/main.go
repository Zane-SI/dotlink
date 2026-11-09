// Command dotlink-agent is the per-Node side: it enrolls, brings the tunnel
// up, and answers questions about what it can reach.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Zane-SI/dotlink/internal/agent"
	"github.com/Zane-SI/dotlink/internal/proto"
)

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

func runUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	listen := fs.String("listen", agent.DefaultUDPListen, "UDP listen address; the same socket carries Relay traffic and hole punching")
	derpAddr := fs.String("derp", "", "DERP endpoint to use instead of the one in the Peer Map")
	relayOnly := fs.Bool("relay-only", false, "skip hole punching and stay on the Relay")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := agent.LoadState()
	if err != nil {
		return err
	}

	// A Ctrl-C must take the TUN and its routes down with it; the daemon
	// cleans up on context cancellation.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	d := &agent.Daemon{State: st, UDPListen: *listen, DERPAddr: *derpAddr, NoPunch: *relayOnly}
	return d.Run(ctx)
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
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
	fmt.Fprintln(w, "HOSTNAME\tIPV4\tIPV6\tONLINE\tLAST SEEN")
	for _, p := range pm.Peers {
		online := "no"
		if p.Online {
			online = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			p.Hostname, p.IPv4, p.IPv6, online, p.LastSeen.Local().Format(time.RFC3339))
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
