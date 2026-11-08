package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Zane-SI/dotlink/internal/proto"
)

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	row, err := s.createInvite(s.now())
	if err != nil {
		s.fail(w, "create invite", err)
		return
	}
	// An Invite is not part of the Peer Map, so it does not bump the version:
	// waking every Agent for a credential that no Node can see would be noise.
	writeJSON(w, http.StatusCreated, s.toProtoInvite(row))
}

func (s *Server) handleListInvites(w http.ResponseWriter, r *http.Request) {
	rows, err := s.listInvites()
	if err != nil {
		s.fail(w, "list invites", err)
		return
	}
	out := make([]proto.Invite, 0, len(rows))
	for _, row := range rows {
		out = append(out, s.toProtoInvite(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

func (s *Server) handleDeleteInvite(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		writeError(w, http.StatusNotFound, "invite not found")
		return
	}
	if err := s.deleteInvite(id); err != nil {
		s.storeError(w, err, "invite not found or already used")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// enrollURL renders the dotlink:// URL for the QR code. It carries the Control
// Plane address and the one-shot invite token — never key material.
func (s *Server) enrollURL(token string) string {
	return fmt.Sprintf("dotlink://enroll?v=1&u=%s&t=%s&n=%s",
		url.QueryEscape(s.cfg.PublicURL),
		url.QueryEscape(token),
		url.QueryEscape(s.cfg.NetworkName))
}

// toProtoInvite converts a storage row into the wire type.
func (s *Server) toProtoInvite(row inviteRow) proto.Invite {
	return proto.Invite{
		ID:        row.ID,
		Token:     row.Token,
		URL:       s.enrollURL(row.Token),
		ExpiresAt: row.ExpiresAt.UTC(),
		UsedBy:    row.UsedBy,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// A write failure here means the client hung up; there is nobody to tell.
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func methodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// fail logs the cause and answers 500 without leaking internals to the caller.
func (s *Server) fail(w http.ResponseWriter, op string, err error) {
	s.log.Error(op, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// storeError maps the three storage outcomes every handler shares.
func (s *Server) storeError(w http.ResponseWriter, err error, notFoundMsg string) {
	switch err {
	case nil:
	case errNotFound:
		writeError(w, http.StatusNotFound, notFoundMsg)
	case errInviteUsed:
		writeError(w, http.StatusConflict, "invite already used")
	case errInviteExpired:
		writeError(w, http.StatusGone, "invite expired")
	default:
		s.fail(w, "storage", err)
	}
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req proto.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed JSON body")
		return
	}
	if req.Invite == "" || req.Pubkey == "" || req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "invite, pubkey and hostname are required")
		return
	}

	row, err := s.enroll(req, s.now())
	if err != nil {
		s.storeError(w, err, "invite not found")
		return
	}
	if err := s.bumpVersion(); err != nil {
		s.fail(w, "bump version", err)
		return
	}

	s.log.Info("node enrolled", "node", row.ID, "hostname", row.Hostname, "ipv4", row.IPv4)
	writeJSON(w, http.StatusOK, proto.EnrollResponse{
		NodeID:     row.ID,
		NodeToken:  row.NodeToken,
		IPv4:       row.IPv4,
		IPv6:       row.IPv6,
		Network:    s.network(),
		Relays:     s.relays(),
		MapVersion: s.currentVersion(),
	})
}

func (s *Server) handleMap(w http.ResponseWriter, r *http.Request) {
	node, ok := s.requireNode(w, r)
	if !ok {
		return
	}

	since := int64(-1)
	if raw := r.URL.Query().Get("since"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be an integer")
			return
		}
		since = v
	}

	// Polling is the liveness signal until heartbeats land in a later ticket.
	if err := s.touchNode(node.ID, s.now()); err != nil {
		s.log.Warn("touch node", "node", node.ID, "err", err)
	}

	if since == s.currentVersion() {
		if !s.waitForChange(r.Context(), since, s.cfg.LongPollTimeout) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	pm, err := s.buildMap(node)
	if err != nil {
		s.fail(w, "build map", err)
		return
	}
	writeJSON(w, http.StatusOK, pm)
}

// buildMap renders the whole Network from one Node's point of view.
func (s *Server) buildMap(self nodeRow) (proto.PeerMap, error) {
	nodes, err := s.listNodes()
	if err != nil {
		return proto.PeerMap{}, err
	}
	now := s.now()

	peers := make([]proto.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.ID == self.ID {
			continue
		}
		peers = append(peers, proto.Node{
			NodeID:       n.ID,
			Hostname:     n.Hostname,
			Pubkey:       n.Pubkey,
			IPv4:         n.IPv4,
			IPv6:         n.IPv6,
			Candidates:   orEmpty(n.Candidates),
			SubnetRoutes: orEmpty(n.Subnets),
			Online:       isOnline(now, n.LastSeen),
			LastSeen:     n.LastSeen,
		})
	}

	return proto.PeerMap{
		Version: s.currentVersion(),
		Self: proto.Self{
			NodeID:   self.ID,
			IPv4:     self.IPv4,
			IPv6:     self.IPv6,
			Hostname: self.Hostname,
		},
		Network: s.network(),
		Peers:   peers,
		Relays:  s.relays(),
	}, nil
}

func (s *Server) network() proto.Network {
	return proto.Network{Name: s.cfg.NetworkName, Domain: s.cfg.Domain}
}

// relays never returns nil, so the JSON is [] rather than null.
func (s *Server) relays() []proto.Relay { return orEmpty(s.cfg.Relays) }

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.listNodes()
	if err != nil {
		s.fail(w, "list nodes", err)
		return
	}
	now := s.now()
	out := make([]adminNode, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, adminNode{
			NodeID:   n.ID,
			Hostname: n.Hostname,
			OS:       n.OS,
			IPv4:     n.IPv4,
			IPv6:     n.IPv6,
			Pubkey:   n.Pubkey,
			Online:   isOnline(now, n.LastSeen),
			LastSeen: n.LastSeen,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

// adminNode is the operator's view: a Node plus the fields the Peer Map hides.
type adminNode struct {
	NodeID   string    `json:"node_id"`
	Hostname string    `json:"hostname"`
	OS       string    `json:"os"`
	IPv4     string    `json:"ipv4"`
	IPv6     string    `json:"ipv6"`
	Pubkey   string    `json:"pubkey"`
	Online   bool      `json:"online"`
	LastSeen time.Time `json:"last_seen"`
}

func (s *Server) handleRevokeNode(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err := s.revokeNode(id); err != nil {
		s.storeError(w, err, "node not found")
		return
	}
	if err := s.bumpVersion(); err != nil {
		s.log.Error("bump version after revoke", "node", id, "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}
