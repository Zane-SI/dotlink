package control

import (
	"encoding/json"
	"fmt"
	"log"
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
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// An Invite is not part of the Peer Map, so it does not bump the version:
	// waking every Agent for a credential that no Peer can see would be noise.
	writeJSON(w, http.StatusCreated, s.toProtoInvite(row))
}

func (s *Server) handleListInvites(w http.ResponseWriter, r *http.Request) {
	rows, err := s.listInvites()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
		http.NotFound(w, r)
		return
	}
	switch err := s.deleteInvite(id); err {
	case nil:
		w.WriteHeader(http.StatusNoContent)
	case errNotFound:
		writeError(w, http.StatusNotFound, "invite not found or already used")
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
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
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func methodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
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
	switch err {
	case nil:
	case errNotFound:
		writeError(w, http.StatusNotFound, "invite not found")
		return
	case errInviteUsed:
		writeError(w, http.StatusConflict, "invite already used")
		return
	case errInviteExpired:
		writeError(w, http.StatusGone, "invite expired")
		return
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := s.bumpVersion(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, proto.EnrollResponse{
		NodeID:     row.ID,
		NodeToken:  row.NodeToken,
		IPv4:       row.IPv4,
		IPv6:       row.IPv6,
		Network:    proto.Network{Name: s.cfg.NetworkName, Domain: s.cfg.Domain},
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
		log.Printf("touch node %s: %v", node.ID, err)
	}

	if since == s.currentVersion() {
		if !s.waitForChange(r.Context(), since, s.cfg.LongPollTimeout) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	pm, err := s.buildMap(node)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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

	peers := make([]proto.Peer, 0, len(nodes))
	for _, n := range nodes {
		if n.ID == self.ID {
			continue
		}
		cands := n.Candidates
		if cands == nil {
			cands = []proto.Candidate{}
		}
		subnets := n.Subnets
		if subnets == nil {
			subnets = []string{}
		}
		peers = append(peers, proto.Peer{
			NodeID:       n.ID,
			Hostname:     n.Hostname,
			Pubkey:       n.Pubkey,
			IPv4:         n.IPv4,
			IPv6:         n.IPv6,
			Candidates:   cands,
			SubnetRoutes: subnets,
			Online:       now.Sub(n.LastSeen) < onlineWindow,
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
		Network: proto.Network{Name: s.cfg.NetworkName, Domain: s.cfg.Domain},
		Peers:   peers,
		Relays:  s.relays(),
	}, nil
}

// relays never returns nil, so the JSON is [] rather than null.
func (s *Server) relays() []proto.Relay {
	if len(s.cfg.Relays) == 0 {
		return []proto.Relay{}
	}
	return s.cfg.Relays
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.listNodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
			Online:   now.Sub(n.LastSeen) < onlineWindow,
			LastSeen: n.LastSeen,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
}

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
		http.NotFound(w, r)
		return
	}
	switch err := s.revokeNode(id); err {
	case nil:
		if err := s.bumpVersion(); err != nil {
			log.Printf("bump version: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	case errNotFound:
		writeError(w, http.StatusNotFound, "node not found")
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
