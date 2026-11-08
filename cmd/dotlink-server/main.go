// Command dotlink-server runs the Control Plane and, in later tickets, the
// Relay. Today: `control` to serve the API, `invite` to mint a QR link.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Zane-SI/dotlink/internal/control"
	"github.com/Zane-SI/dotlink/internal/proto"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "control":
		err = runControl(os.Args[2:])
	case "invite":
		err = runInvite(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "dotlink-server: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dotlink-server — Dotlink Control Plane

  dotlink-server control [flags]   serve the API
  dotlink-server invite  [flags]   mint a one-shot invite link

Run "dotlink-server <command> -h" for flags.
`)
}

func runControl(args []string) error {
	fs := flag.NewFlagSet("control", flag.ExitOnError)
	db := fs.String("db", "dotlink.db", "SQLite file holding Nodes and Invites")
	addr := fs.String("addr", ":8443", "listen address")
	publicURL := fs.String("public-url", "", "address Agents reach, e.g. https://203.0.113.7:8443 (defaults to http://<addr>)")
	network := fs.String("network", "home", "Network name")
	domain := fs.String("domain", "dotlink", "MagicDNS pseudo-TLD")
	adminToken := fs.String("admin-token", "", "admin token (generated once and printed on first start when empty)")
	tlsCert := fs.String("tls-cert", "", "PEM certificate; with -tls-key, serve HTTPS (spec §8)")
	tlsKey := fs.String("tls-key", "", "PEM private key")
	relayUDP := fs.String("relay-udp", "", "Relay UDP address handed to Agents")
	relayDERP := fs.String("relay-derp", "", "Relay DERP URL handed to Agents")
	if err := fs.Parse(args); err != nil {
		return err
	}

	url := *publicURL
	if url == "" {
		host, port, err := net.SplitHostPort(*addr)
		if err != nil {
			return fmt.Errorf("parse -addr %q: %w", *addr, err)
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		scheme := "http"
		if *tlsCert != "" {
			scheme = "https"
		}
		url = scheme + "://" + net.JoinHostPort(host, port)
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return fmt.Errorf("-tls-cert and -tls-key must be given together")
	}

	cfg := control.Config{
		DBPath:      *db,
		AdminToken:  *adminToken,
		PublicURL:   url,
		NetworkName: *network,
		Domain:      *domain,
	}
	if *relayUDP != "" || *relayDERP != "" {
		cfg.Relays = []proto.Relay{{ID: "relay-1", UDP: *relayUDP, DERP: *relayDERP}}
	}

	srv, err := control.Open(cfg)
	if err != nil {
		return err
	}
	defer srv.Close()

	if srv.GeneratedAdminToken {
		fmt.Printf("admin token: %s\n", srv.AdminToken)
		fmt.Println("             generated once and stored in the database; save it now")
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *addr, err)
	}
	fmt.Printf("listening on %s (public URL %s)\n", *addr, url)
	fmt.Printf("network %q, MagicDNS domain .%s\n", *network, *domain)
	httpSrv := &http.Server{Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	if *tlsCert != "" {
		return httpSrv.ServeTLS(ln, *tlsCert, *tlsKey)
	}
	return httpSrv.Serve(ln)
}

func runInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	server := fs.String("server", "https://127.0.0.1:8443", "Control Plane address")
	adminToken := fs.String("admin-token", "", "admin token (or set DOTLINK_ADMIN_TOKEN)")
	jsonOut := fs.Bool("json", false, "print the raw JSON response")
	if err := fs.Parse(args); err != nil {
		return err
	}

	token := *adminToken
	if token == "" {
		token = os.Getenv("DOTLINK_ADMIN_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("admin token required: pass -admin-token or set DOTLINK_ADMIN_TOKEN")
	}

	url := strings.TrimRight(*server, "/")
	if !strings.Contains(url, "://") {
		url = "https://" + url
	}
	inv, err := control.NewAdmin(url, token).CreateInvite(context.Background())
	if err != nil {
		return err
	}

	if *jsonOut {
		b, err := json.MarshalIndent(inv, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", b)
		return nil
	}
	fmt.Printf("invite token: %s\n", inv.Token)
	fmt.Printf("enroll link:  %s\n", inv.URL)
	fmt.Printf("expires:      %s (one shot)\n", inv.ExpiresAt.Local().Format(time.RFC1123))
	return nil
}
