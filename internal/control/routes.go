package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/Zane-SI/dotlink/internal/subnet"
)

// routeConflict is returned when two Nodes claim the same LAN. Routing there
// would be a coin flip, so the second advertisement is refused with enough
// information to find both machines. An offline claim still conflicts: the
// Node keeps its addresses and its routes, and two Gateways for one LAN would
// split the traffic unpredictably.
type routeConflict struct {
	// Route is the prefix the requester tried to advertise; HolderRoute is
	// the existing route it overlapped. They differ when the clash is an
	// overlap rather than an exact match, and naming both is what tells the
	// operator which of the two boxes to fix.
	Route             string
	HolderRoute       string
	NodeID            string
	Hostname          string
	RequesterID       string
	RequesterHostname string
}

func (e *routeConflict) Error() string {
	return fmt.Sprintf("%s is already advertised by %s (%s); this Node is %s (%s) and tried to advertise %s",
		e.HolderRoute, e.Hostname, e.NodeID, e.RequesterHostname, e.RequesterID, e.Route)
}

// handlePostRoutes records the subnets a Gateway forwards for. Like
// candidates, this is what every other Node installs as a route, so it is
// validated and checked for collisions before it is stored.
func (s *Server) handlePostRoutes(w http.ResponseWriter, r *http.Request) {
	node, ok := s.requireNode(w, r)
	if !ok {
		return
	}
	var req struct {
		Routes []string `json:"routes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON with a routes array")
		return
	}
	routes, err := cleanRoutes(req.Routes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	changed, err := s.setSubnets(node, routes)
	if err != nil {
		var clash *routeConflict
		if errors.As(err, &clash) {
			writeError(w, http.StatusConflict, clash.Error())
			return
		}
		s.fail(w, "set routes", err)
		return
	}
	if changed {
		if err := s.bumpVersion(); err != nil {
			s.fail(w, "bump version", err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// cleanRoutes canonicalizes and sanity-checks an advertisement. The rules live
// in internal/subnet so the Agent rejects the same input before it touches a
// TUN, instead of discovering the problem only after a 400 from here.
func cleanRoutes(in []string) ([]string, error) {
	return subnet.Parse(in)
}

// setSubnets stores the advertisement after checking it against every other
// Node. The check runs inside the same transaction as the write so two
// Gateways cannot both see a free LAN and both claim it.
func (s *Server) setSubnets(node nodeRow, routes []string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	mine, err := parseRoutes(routes)
	if err != nil {
		return false, err
	}
	rows, err := tx.Query(`SELECT id, hostname, subnets FROM nodes WHERE revoked = 0 AND id <> ?`, node.ID)
	if err != nil {
		return false, fmt.Errorf("lookup routes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			otherID, hostname, raw string
		)
		if err := rows.Scan(&otherID, &hostname, &raw); err != nil {
			return false, err
		}
		var theirs []string
		if err := json.Unmarshal([]byte(raw), &theirs); err != nil {
			continue
		}
		theirsParsed, err := parseRoutes(theirs)
		if err != nil {
			continue
		}
		for _, a := range mine {
			for _, b := range theirsParsed {
				if a.Overlaps(b) {
					return false, &routeConflict{
						Route:             a.String(),
						HolderRoute:       b.String(),
						NodeID:            otherID,
						Hostname:          hostname,
						RequesterID:       node.ID,
						RequesterHostname: node.Hostname,
					}
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}

	encoded, err := json.Marshal(routes)
	if err != nil {
		return false, fmt.Errorf("marshal routes: %w", err)
	}
	res, err := tx.Exec(
		`UPDATE nodes SET subnets = ? WHERE id = ? AND subnets <> ?`,
		string(encoded), node.ID, string(encoded))
	if err != nil {
		return false, fmt.Errorf("set routes: %w", err)
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return changed == 1, nil
}

func parseRoutes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, raw := range in {
		pr, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("stored route %q is not a prefix", raw)
		}
		out = append(out, pr.Masked())
	}
	return out, nil
}
