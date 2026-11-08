package agent

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Zane-SI/dotlink/internal/ctlapi"
	"github.com/Zane-SI/dotlink/internal/proto"
)

// Control is this Agent's connection to the Control Plane. It is not the
// glossary's "Client" (the user-facing app) and not an admin handle: it holds
// exactly one Node's token.
type Control struct {
	ctlapi.Client
}

// Control returns a handle authenticated as this Node.
func (st State) Control() *Control {
	return &Control{Client: ctlapi.Client{
		BaseURL: st.Server,
		Token:   st.NodeToken,
		HTTP:    DefaultHTTPClient(),
	}}
}

// DefaultHTTPClient outlives the Control Plane's 50-second long poll.
func DefaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 70 * time.Second}
}

// Enroll redeems an Invite and returns the identity to save. The keypair is
// generated here; only the public half ever leaves the machine.
func Enroll(ctx context.Context, link EnrollLink, hostname, osName string) (State, error) {
	priv, pub, err := GenerateKey()
	if err != nil {
		return State{}, err
	}
	server, err := NormalizeServer(link.Server)
	if err != nil {
		return State{}, err
	}

	c := &Control{Client: ctlapi.Client{BaseURL: server, HTTP: DefaultHTTPClient()}}
	var resp proto.EnrollResponse
	if err := c.Do(ctx, http.MethodPost, "/v1/enroll", proto.EnrollRequest{
		Invite:   link.Invite,
		Pubkey:   pub,
		Hostname: hostname,
		OS:       osName,
	}, &resp); err != nil {
		return State{}, err
	}

	return State{
		Server:    server,
		NodeID:    resp.NodeID,
		NodeToken: resp.NodeToken,
		IPv4:      resp.IPv4,
		IPv6:      resp.IPv6,
		Hostname:  hostname,
		PrivKey:   priv,
		Network:   resp.Network,
		Version:   resp.MapVersion,
	}, nil
}

// SetCandidates publishes the addresses peers can try to reach this Node at.
func (c *Control) SetCandidates(ctx context.Context, cands []proto.Candidate) error {
	return c.Do(ctx, http.MethodPost, "/v1/candidates", struct {
		Candidates []proto.Candidate `json:"candidates"`
	}{cands}, nil)
}

// Heartbeat refreshes this Node's last_seen without asking for the map.
func (c *Control) Heartbeat(ctx context.Context) error {
	status, err := c.DoStatus(ctx, http.MethodPost, "/v1/heartbeat", nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("heartbeat: unexpected status %d", status)
	}
	return nil
}

// Map long-polls the Peer Map. It returns nil when the Control Plane had
// nothing new within its long-poll window (HTTP 204).
func (c *Control) Map(ctx context.Context, since int64) (*proto.PeerMap, error) {
	var pm proto.PeerMap
	status, err := c.DoStatus(ctx, http.MethodGet, fmt.Sprintf("/v1/map?since=%d", since), nil, &pm)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	return &pm, nil
}
