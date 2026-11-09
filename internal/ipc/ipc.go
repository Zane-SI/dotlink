// Package ipc is the local control channel between a Client (the menu bar
// app) and the Agent.
//
// It is a Unix socket, not a TCP port: the thing on the other end can open the
// TUN device and rewrite routes, so "any process on the machine" is already
// too broad a trust boundary to hand a network listener to. The socket is
// root:admin 0660, and the admin group is the same group that can already
// install a launch daemon.
package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// DefaultSocket is where the Agent listens and the Client dials.
const DefaultSocket = "/var/run/dotlink.sock"

// Status is everything the menu bar needs to draw itself.
type Status struct {
	Running    bool   `json:"running"`
	PID        int    `json:"pid,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	IPv4       string `json:"ipv4,omitempty"`
	IPv6       string `json:"ipv6,omitempty"`
	RelayUDP   string `json:"relay_udp,omitempty"`
	RelayMode  string `json:"relay_mode,omitempty"`
	Registered bool   `json:"registered"`

	// CanInvite says whether this Agent holds a Control Plane admin token,
	// which is what it takes to sign a QR code. A Node that is not the
	// Gateway can still see the network; it just cannot hand out keys.
	CanInvite bool `json:"can_invite"`
	// Network is the network name shown next to the QR code.
	Network string `json:"network,omitempty"`
	// AdvertiseRoutes are the LANs this Agent forwards for, if it is a
	// Subnet Router. Empty means it is an ordinary Node.
	AdvertiseRoutes []string `json:"advertise_routes,omitempty"`
	// Error is the last reason the tunnel is not running, if any.
	Error string `json:"error,omitempty"`

	Peers []Peer `json:"peers"`
}

// Peer is one Node as this Agent currently reaches it.
type Peer struct {
	Hostname string `json:"hostname"`
	IPv4     string `json:"ipv4,omitempty"`
	Path     string `json:"path"`             // "Direct" or "Relayed"
	RTTms    int64  `json:"rtt_ms,omitempty"` // only meaningful on a direct path
}

// Invite is a freshly signed QR code, in the form the menu bar renders.
type Invite struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Provider is what the socket exposes. The Agent implements it; tests fake it.
type Provider interface {
	Status(ctx context.Context) (Status, error)
	CreateInvite(ctx context.Context) (Invite, error)
	Disconnect(ctx context.Context) error
	Connect(ctx context.Context) error
}

// Server serves the socket.
type Server struct {
	// Path is the socket path. Empty means DefaultSocket.
	Path string
	// Group is the group allowed to talk to the socket. Empty means "admin"
	// on macOS, and the current group elsewhere.
	Group string

	Provider Provider
	Logger   *slog.Logger

	mu  sync.Mutex
	srv *http.Server
	ln  net.Listener
}

const socketMode = 0o660

// ListenAndServe binds the socket and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	log := s.logger()
	path := s.path()
	// A socket file left by a crash would make Listen fail with "address
	// already in use" long after the process that owned it is gone.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen %s: %w", path, err)
	}
	if err := s.restrict(path); err != nil {
		ln.Close()
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		st, err := s.Provider.Status(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, st)
	})
	mux.HandleFunc("/invite", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		inv, err := s.Provider.CreateInvite(r.Context())
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, inv)
	})
	mux.HandleFunc("/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if err := s.Provider.Disconnect(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if err := s.Provider.Connect(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	s.mu.Lock()
	s.srv, s.ln = srv, ln
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Info("agent socket listening", "path", path)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Close stops serving and removes the socket file, so a reinstall does not
// inherit a dead endpoint.
func (s *Server) Close() error {
	s.mu.Lock()
	srv, ln := s.srv, s.ln
	s.mu.Unlock()
	var err error
	if srv != nil {
		err = srv.Close()
	}
	if ln != nil {
		_ = ln.Close()
	}
	if rmErr := os.Remove(s.path()); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) && err == nil {
		err = rmErr
	}
	return err
}

func (s *Server) path() string {
	if s.Path != "" {
		return s.Path
	}
	return DefaultSocket
}

// restrict makes the socket root:admin 0660. Any user who can reach it can
// bring the tunnel up or down, so 0666 would be a remote-control bug.
func (s *Server) restrict(path string) error {
	if err := os.Chmod(path, socketMode); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		// Running unprivileged (tests, `go run`): there is no root to hand the
		// socket to, and chown would fail anyway.
		return nil
	}
	group := s.Group
	if group == "" {
		group = "admin"
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("look up group %q: %w", group, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, 0, gid)
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
