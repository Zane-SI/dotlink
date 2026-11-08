package control

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Zane-SI/dotlink/internal/proto"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS invites (
	id         TEXT PRIMARY KEY,
	token      TEXT NOT NULL UNIQUE,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	used_by    TEXT
);

CREATE TABLE IF NOT EXISTS nodes (
	id         TEXT PRIMARY KEY,
	hostname   TEXT NOT NULL,
	os         TEXT NOT NULL,
	pubkey     TEXT NOT NULL,
	ipv4       TEXT NOT NULL UNIQUE,
	ipv6       TEXT NOT NULL UNIQUE,
	node_token TEXT NOT NULL UNIQUE,
	created_at INTEGER NOT NULL,
	last_seen  INTEGER,
	path       TEXT NOT NULL DEFAULT 'unknown',
	candidates TEXT NOT NULL DEFAULT '[]',
	subnets    TEXT NOT NULL DEFAULT '[]',
	revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

var (
	// errNotFound means the row is absent or has been revoked.
	errNotFound = errors.New("not found")
	// errInviteUsed means the Invite was already redeemed (one-shot).
	errInviteUsed = errors.New("invite already used")
	// errInviteExpired means the Invite is past its 24-hour window.
	errInviteExpired = errors.New("invite expired")
)

// inviteTTL is the Invite lifetime from spec §3.2: one-shot, 24 hours.
const inviteTTL = 24 * time.Hour

var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// newToken returns prefix followed by nbytes of randomness in lowercase base32.
func newToken(prefix string, nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return prefix + strings.ToLower(tokenEncoding.EncodeToString(b)), nil
}

func (s *Server) openDB(path string) error {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return fmt.Errorf("apply schema: %w", err)
	}
	s.db = db
	return nil
}

// inviteRow is the storage shape of an Invite.
type inviteRow struct {
	ID        string
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedBy    string
}

func (s *Server) createInvite(now time.Time) (inviteRow, error) {
	id, err := newToken("inv_", 5)
	if err != nil {
		return inviteRow{}, err
	}
	token, err := newToken("dlk_inv_", 15)
	if err != nil {
		return inviteRow{}, err
	}
	row := inviteRow{ID: id, Token: token, CreatedAt: now, ExpiresAt: now.Add(inviteTTL)}
	_, err = s.db.Exec(
		`INSERT INTO invites (id, token, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		row.ID, row.Token, row.CreatedAt.Unix(), row.ExpiresAt.Unix(),
	)
	if err != nil {
		return inviteRow{}, fmt.Errorf("insert invite: %w", err)
	}
	return row, nil
}

func (s *Server) listInvites() ([]inviteRow, error) {
	rows, err := s.db.Query(
		`SELECT id, token, created_at, expires_at, coalesce(used_by, '') FROM invites ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list invites: %w", err)
	}
	defer rows.Close()

	var out []inviteRow
	for rows.Next() {
		var r inviteRow
		var created, expires int64
		if err := rows.Scan(&r.ID, &r.Token, &created, &expires, &r.UsedBy); err != nil {
			return nil, fmt.Errorf("scan invite: %w", err)
		}
		r.CreatedAt = time.Unix(created, 0).UTC()
		r.ExpiresAt = time.Unix(expires, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// deleteInvite removes an unused Invite. A redeemed Invite is history: it stays.
func (s *Server) deleteInvite(id string) error {
	res, err := s.db.Exec(`DELETE FROM invites WHERE id = ? AND used_by IS NULL`, id)
	if err != nil {
		return fmt.Errorf("delete invite: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return errNotFound
	}
	return nil
}

// nodeRow is the storage shape of a Node.
type nodeRow struct {
	ID         string
	Hostname   string
	OS         string
	Pubkey     string
	IPv4       string
	IPv6       string
	NodeToken  string
	CreatedAt  time.Time
	LastSeen   time.Time
	Path       string
	Candidates []proto.Candidate
	Subnets    []string
}

// onlineWindow is how long after the last request a Node still counts as
// online. Heartbeats are a later ticket; for now, polling the map is the
// liveness signal.
const onlineWindow = 2 * time.Minute

// enroll redeems an Invite and creates the Node in one transaction, so a crash
// can never leave an Invite spent without a Node behind it.
func (s *Server) enroll(req proto.EnrollRequest, now time.Time) (nodeRow, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nodeRow{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	var (
		inviteID  string
		expiresAt int64
		usedBy    sql.NullString
	)
	err = tx.QueryRow(
		`SELECT id, expires_at, used_by FROM invites WHERE token = ?`, req.Invite,
	).Scan(&inviteID, &expiresAt, &usedBy)
	if err == sql.ErrNoRows {
		return nodeRow{}, errNotFound
	}
	if err != nil {
		return nodeRow{}, fmt.Errorf("lookup invite: %w", err)
	}
	if usedBy.Valid {
		return nodeRow{}, errInviteUsed
	}
	if now.After(time.Unix(expiresAt, 0)) {
		return nodeRow{}, errInviteExpired
	}

	nodeID, err := newToken("n_", 5)
	if err != nil {
		return nodeRow{}, err
	}
	nodeToken, err := newToken("dlk_nt_", 15)
	if err != nil {
		return nodeRow{}, err
	}
	n, err := allocAddr(tx)
	if err != nil {
		return nodeRow{}, err
	}

	row := nodeRow{
		ID:         nodeID,
		Hostname:   req.Hostname,
		OS:         req.OS,
		Pubkey:     req.Pubkey,
		IPv4:       fmt.Sprintf("100.64.%d.%d", (n-1)/254, (n-1)%254+1),
		IPv6:       fmt.Sprintf("fd00::%x", n),
		NodeToken:  nodeToken,
		CreatedAt:  now,
		LastSeen:   now,
		Path:       "unknown",
		Candidates: req.Candidates,
		Subnets:    []string{},
	}

	cand, err := json.Marshal(row.Candidates)
	if err != nil {
		return nodeRow{}, fmt.Errorf("marshal candidates: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO nodes (id, hostname, os, pubkey, ipv4, ipv6, node_token, created_at, last_seen, path, candidates, subnets)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]')`,
		row.ID, row.Hostname, row.OS, row.Pubkey, row.IPv4, row.IPv6,
		row.NodeToken, row.CreatedAt.Unix(), row.LastSeen.Unix(), row.Path, string(cand),
	); err != nil {
		return nodeRow{}, fmt.Errorf("insert node: %w", err)
	}
	if _, err := tx.Exec(`UPDATE invites SET used_by = ? WHERE id = ?`, row.ID, inviteID); err != nil {
		return nodeRow{}, fmt.Errorf("mark invite used: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nodeRow{}, fmt.Errorf("commit: %w", err)
	}
	return row, nil
}

// allocAddr hands out the next address index. 100.64.0.1 is index 1.
func allocAddr(tx *sql.Tx) (int, error) {
	var raw string
	err := tx.QueryRow(`SELECT value FROM meta WHERE key = 'next_ip'`).Scan(&raw)
	next := 1
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return 0, fmt.Errorf("read next_ip: %w", err)
	default:
		if next, err = strconv.Atoi(raw); err != nil {
			return 0, fmt.Errorf("parse next_ip %q: %w", raw, err)
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO meta (key, value) VALUES ('next_ip', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		strconv.Itoa(next+1)); err != nil {
		return 0, fmt.Errorf("write next_ip: %w", err)
	}
	return next, nil
}

const nodeColumns = `id, hostname, os, pubkey, ipv4, ipv6, node_token, created_at, coalesce(last_seen, 0), path, candidates, subnets`

func scanNode(row interface{ Scan(...any) error }) (nodeRow, error) {
	var (
		n        nodeRow
		created  int64
		lastSeen int64
		cand     string
		subnets  string
	)
	if err := row.Scan(&n.ID, &n.Hostname, &n.OS, &n.Pubkey, &n.IPv4, &n.IPv6,
		&n.NodeToken, &created, &lastSeen, &n.Path, &cand, &subnets); err != nil {
		return nodeRow{}, err
	}
	n.CreatedAt = time.Unix(created, 0).UTC()
	if lastSeen > 0 {
		n.LastSeen = time.Unix(lastSeen, 0).UTC()
	}
	if err := json.Unmarshal([]byte(cand), &n.Candidates); err != nil {
		return nodeRow{}, fmt.Errorf("decode candidates: %w", err)
	}
	if err := json.Unmarshal([]byte(subnets), &n.Subnets); err != nil {
		return nodeRow{}, fmt.Errorf("decode subnets: %w", err)
	}
	return n, nil
}

// nodeByToken authenticates a request from an Agent.
func (s *Server) nodeByToken(token string) (nodeRow, error) {
	row := s.db.QueryRow(
		`SELECT `+nodeColumns+` FROM nodes WHERE node_token = ? AND revoked = 0`, token)
	n, err := scanNode(row)
	if err == sql.ErrNoRows {
		return nodeRow{}, errNotFound
	}
	return n, err
}

// touchNode records liveness without bumping the map version: polling is not
// a change other Nodes need to hear about.
func (s *Server) touchNode(id string, now time.Time) error {
	_, err := s.db.Exec(`UPDATE nodes SET last_seen = ? WHERE id = ?`, now.Unix(), id)
	return err
}

// listNodes returns every live Node, oldest first.
func (s *Server) listNodes() ([]nodeRow, error) {
	rows, err := s.db.Query(`SELECT ` + nodeColumns + ` FROM nodes WHERE revoked = 0 ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()

	var out []nodeRow
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// revokeNode makes a Node's token worthless and drops it from every Peer Map.
func (s *Server) revokeNode(id string) error {
	res, err := s.db.Exec(`UPDATE nodes SET revoked = 1 WHERE id = ? AND revoked = 0`, id)
	if err != nil {
		return fmt.Errorf("revoke node: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return errNotFound
	}
	return nil
}
