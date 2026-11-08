package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Zane-SI/dotlink/internal/proto"
)

// Client talks to one Control Plane on behalf of one Node.
type Client struct {
	Server string
	Token  string
	HTTP   *http.Client
}

// Client returns a Client authenticated as this Node.
func (st State) Client() *Client {
	return &Client{Server: st.Server, Token: st.NodeToken, HTTP: DefaultHTTPClient()}
}

// DefaultHTTPClient outlives the Control Plane's 50-second long poll.
func DefaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 70 * time.Second}
}

func (c *Client) do(method, path string, body, out any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimSuffix(c.Server, "/")+path, rdr)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return resp, fmt.Errorf("%s %s: %d: %s", method, path, resp.StatusCode, e.Error)
		}
		return resp, fmt.Errorf("%s %s: %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, fmt.Errorf("decode %s %s: %w", method, path, err)
		}
	}
	return resp, nil
}

// Enroll redeems an Invite and returns the identity to save.
func Enroll(link EnrollLink, hostname, osName string) (State, error) {
	priv, pub, err := GenerateKey()
	if err != nil {
		return State{}, err
	}
	server, err := NormalizeServer(link.Server)
	if err != nil {
		return State{}, err
	}

	c := &Client{Server: server, HTTP: DefaultHTTPClient()}
	var resp proto.EnrollResponse
	if _, err := c.do(http.MethodPost, "/v1/enroll", proto.EnrollRequest{
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

// Map long-polls the Peer Map. It returns nil when the Control Plane had
// nothing new within its long-poll window (HTTP 204).
func (c *Client) Map(since int64) (*proto.PeerMap, error) {
	var pm proto.PeerMap
	resp, err := c.do(http.MethodGet, fmt.Sprintf("/v1/map?since=%d", since), nil, &pm)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	return &pm, nil
}

// CreateInvite mints a one-shot Invite. The Client must hold an admin token.
func (c *Client) CreateInvite() (proto.Invite, error) {
	var inv proto.Invite
	if _, err := c.do(http.MethodPost, "/v1/admin/invites", struct{}{}, &inv); err != nil {
		return proto.Invite{}, err
	}
	return inv, nil
}
