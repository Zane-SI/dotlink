package control

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Zane-SI/dotlink/internal/proto"
)

// Config is everything the Control Plane needs to run. Open fills in defaults,
// so a zero Config is still a usable server.
type Config struct {
	// DBPath is the SQLite file. Use a temp file in tests, never :memory:,
	// because "data survives a restart" is behavior worth testing.
	DBPath string

	// AdminToken authorizes /v1/admin/*. When empty, Open reuses the token in
	// the database, generating one only on first start. Spec §3.1: it is
	// generated once and kept, otherwise every restart would lock the operator
	// out of their own CLI.
	AdminToken string

	// PublicURL is what goes into the QR code, e.g. https://203.0.113.7:8443.
	PublicURL string

	// NetworkName is the single Network this Control Plane serves.
	NetworkName string

	// Domain is the MagicDNS pseudo-TLD, e.g. "dotlink".
	Domain string

	// LongPollTimeout caps how long GET /v1/map may hang. The spec says 50s;
	// tests shrink it so the 204 path does not cost a minute.
	LongPollTimeout time.Duration

	// Relays is what the Agent may fall back to. v1 has exactly one.
	Relays []proto.Relay

	// Now is the clock. Tests substitute a fake one to walk past Invite
	// expiry without sleeping 24 hours.
	Now func() time.Time

	// Logger receives structured JSON logs (spec §9). Nil means JSON on stderr.
	Logger *slog.Logger
}

// Server is the Control Plane. It is an http.Handler, so tests drive it
// through httptest without opening a real port.
type Server struct {
	cfg Config
	db  *sql.DB
	log *slog.Logger

	// AdminToken is the effective token: the configured one, the stored one,
	// or a freshly generated one.
	AdminToken string

	// GeneratedAdminToken reports that this start minted the token, so the CLI
	// knows to print it exactly once instead of on every restart.
	GeneratedAdminToken bool

	mu      sync.Mutex
	version int64
	changes chan struct{} // closed and replaced on every version bump
}

// Open prepares storage and returns a ready Server.
func Open(cfg Config) (*Server, error) {
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("Config.DBPath is required")
	}
	if cfg.NetworkName == "" {
		cfg.NetworkName = "home"
	}
	if cfg.Domain == "" {
		cfg.Domain = "dotlink"
	}
	if cfg.LongPollTimeout <= 0 {
		cfg.LongPollTimeout = 50 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}

	s := &Server{cfg: cfg, log: cfg.Logger, changes: make(chan struct{})}

	if err := s.openDB(cfg.DBPath); err != nil {
		return nil, err
	}
	if err := s.loadVersion(); err != nil {
		s.db.Close()
		return nil, err
	}
	if err := s.resolveAdminToken(cfg.AdminToken); err != nil {
		s.db.Close()
		return nil, err
	}
	return s, nil
}

// resolveAdminToken picks the admin token: configured, else stored, else new.
// Only a new token is reported as generated, so the CLI prints it once.
func (s *Server) resolveAdminToken(configured string) error {
	if configured != "" {
		s.AdminToken = configured
		return nil
	}
	stored, err := s.getMeta("admin_token", "")
	if err != nil {
		return err
	}
	if stored != "" {
		s.AdminToken = stored
		return nil
	}
	token, err := newToken("dlk_adm_", 15)
	if err != nil {
		return err
	}
	if err := s.setMeta("admin_token", token); err != nil {
		return err
	}
	s.AdminToken = token
	s.GeneratedAdminToken = true
	return nil
}

// Close releases the SQLite handle.
func (s *Server) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// ServeHTTP routes the v1 API.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")

	switch {
	case path == "/healthz":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	case path == "/v1/admin/invites":
		if !s.requireAdmin(w, r) {
			return
		}
		switch r.Method {
		case http.MethodPost:
			s.handleCreateInvite(w, r)
		case http.MethodGet:
			s.handleListInvites(w, r)
		default:
			methodNotAllowed(w, http.MethodPost, http.MethodGet)
		}

	case strings.HasPrefix(path, "/v1/admin/invites/"):
		if !s.requireAdmin(w, r) {
			return
		}
		if r.Method != http.MethodDelete {
			methodNotAllowed(w, http.MethodDelete)
			return
		}
		s.handleDeleteInvite(w, r, strings.TrimPrefix(path, "/v1/admin/invites/"))

	case path == "/v1/enroll":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		s.handleEnroll(w, r)

	case path == "/v1/map":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		s.handleMap(w, r)

	case path == "/v1/admin/nodes":
		if !s.requireAdmin(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		s.handleListNodes(w, r)

	case strings.HasPrefix(path, "/v1/admin/nodes/"):
		if !s.requireAdmin(w, r) {
			return
		}
		if r.Method != http.MethodDelete {
			methodNotAllowed(w, http.MethodDelete)
			return
		}
		s.handleRevokeNode(w, r, strings.TrimPrefix(path, "/v1/admin/nodes/"))

	default:
		http.NotFound(w, r)
	}
}

// requireNode writes 401 and reports the zero value unless the request carries
// a live node token.
func (s *Server) requireNode(w http.ResponseWriter, r *http.Request) (nodeRow, bool) {
	tok := bearerToken(r)
	if tok == "" {
		writeError(w, http.StatusUnauthorized, "node token required")
		return nodeRow{}, false
	}
	node, err := s.nodeByToken(tok)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unknown or revoked node token")
		return nodeRow{}, false
	}
	return node, true
}

// requireAdmin writes 401 and reports false unless the request carries the
// admin token.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	tok := bearerToken(r)
	if tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.AdminToken)) == 1 {
		return true
	}
	writeError(w, http.StatusUnauthorized, "admin token required")
	return false
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return h[7:]
	}
	return ""
}

// bumpVersion advances the Peer Map version and wakes every long poll.
func (s *Server) bumpVersion() error {
	s.mu.Lock()
	s.version++
	v := s.version
	close(s.changes)
	s.changes = make(chan struct{})
	s.mu.Unlock()

	return s.setMeta("map_version", strconv.FormatInt(v, 10))
}

func (s *Server) loadVersion() error {
	raw, err := s.getMeta("map_version", "0")
	if err != nil {
		return err
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("parse map_version %q: %w", raw, err)
	}
	s.version = v
	return nil
}

// now reads the injectable clock.
func (s *Server) now() time.Time { return s.cfg.Now() }

func (s *Server) currentVersion() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// waitForChange blocks until the version differs from since, the timeout
// elapses, or the client goes away. It reports whether the map changed.
func (s *Server) waitForChange(ctx context.Context, since int64, d time.Duration) bool {
	s.mu.Lock()
	if s.version != since {
		s.mu.Unlock()
		return true
	}
	ch := s.changes
	s.mu.Unlock()

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}
