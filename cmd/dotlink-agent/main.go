// Command dotlink-agent is the per-Node side. Today it enrolls and reads the
// Peer Map; the tunnel arrives in the next ticket.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"runtime"
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
	case "peers":
		err = runPeers(os.Args[2:])
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
  dotlink-agent peers [flags]                 list the Nodes you can reach
  dotlink-agent status                        show this Node's identity

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

	st, err := agent.Enroll(link, name, runtime.GOOS)
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

	pm, err := st.Client().Map(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not read the Peer Map yet: %v\n", err)
		return nil
	}
	printPeers(pm)
	return nil
}

func runPeers(args []string) error {
	fs := flag.NewFlagSet("peers", flag.ExitOnError)
	watch := fs.Bool("watch", false, "keep long-polling and print the map whenever it changes")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := agent.LoadState()
	if err != nil {
		return err
	}
	client := st.Client()

	if !*watch {
		pm, err := client.Map(0)
		if err != nil {
			return err
		}
		printPeers(pm)
		return nil
	}

	since := st.Version
	for {
		pm, err := client.Map(since)
		if err != nil {
			return err
		}
		if pm == nil {
			continue // long poll timed out with nothing new
		}
		since = pm.Version
		printPeers(pm)
		fmt.Println()
	}
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
	return nil
}

func printPeers(pm *proto.PeerMap) {
	if pm == nil {
		fmt.Println("no map yet")
		return
	}
	fmt.Printf("version %d — self %s (%s)\n", pm.Version, pm.Self.Hostname, pm.Self.IPv4)
	if len(pm.Peers) == 0 {
		fmt.Println("no peers yet: invite another device")
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
