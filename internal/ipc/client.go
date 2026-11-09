package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Client dials the Agent's socket. It is what the menu bar app uses, and what
// `dotlink-agent status` will use once the daemon owns the truth.
type Client struct {
	Path string
	HTTP *http.Client
}

// NewClient returns a client for the given socket path, or DefaultSocket.
func NewClient(path string) *Client {
	if path == "" {
		path = DefaultSocket
	}
	return &Client{
		Path: path,
		HTTP: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", path)
				},
			},
		},
	}
}

// Status asks the Agent what it is doing.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	err := c.do(ctx, http.MethodGet, "/status", nil, &st)
	return st, err
}

// CreateInvite signs a new one-time QR code.
func (c *Client) CreateInvite(ctx context.Context) (Invite, error) {
	var inv Invite
	err := c.do(ctx, http.MethodPost, "/invite", nil, &inv)
	return inv, err
}

// Disconnect tears the tunnel down but leaves the daemon running, so the next
// Connect is instant and no password is asked for.
func (c *Client) Disconnect(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/disconnect", nil, nil)
}

// Connect brings the tunnel back up.
func (c *Client) Connect(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/connect", nil, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://dotlink"+path, r)
	if err != nil {
		return err
	}
	hc := c.HTTP
	if hc == nil {
		hc = NewClient(c.Path).HTTP
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("dotlink agent is not running: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("agent returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
