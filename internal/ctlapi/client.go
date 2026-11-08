// Package ctlapi is the client half of the Control Plane's HTTP API: one
// place that knows how to attach a bearer token, encode a body and turn a
// non-2xx response into an error the caller can inspect.
//
// Both ends of the project use it — the Agent with a node token, the admin CLI
// with the admin token — so the wire plumbing exists once.
package ctlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one Control Plane as one principal.
type Client struct {
	// BaseURL is the Control Plane's public address, e.g. https://host:8443.
	BaseURL string

	// Token is a node token or the admin token, depending on the caller.
	Token string

	// HTTP is the transport. Nil means a client with a 60s timeout, which is
	// longer than the 50s long poll.
	HTTP *http.Client
}

// StatusError is a non-2xx answer. The Control Plane puts a human-readable
// reason in {"error": "..."}.
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("control plane returned %d %s", e.Status, http.StatusText(e.Status))
	}
	return fmt.Sprintf("control plane returned %d: %s", e.Status, e.Message)
}

// NormalizeBase trims trailing slashes so path joins stay predictable.
func NormalizeBase(s string) string { return strings.TrimRight(s, "/") }

// Do sends one request and discards the status. in and out may be nil.
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	_, err := c.DoStatus(ctx, method, path, in, out)
	return err
}

// DoStatus is Do plus the status code, for callers that must tell 204 (nothing
// changed) from 200 (here is the body).
func (c *Client) DoStatus(ctx context.Context, method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, NormalizeBase(c.BaseURL)+path, body)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.http().Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, decodeStatusError(resp)
	}
	if out == nil {
		return resp.StatusCode, nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return resp.StatusCode, fmt.Errorf("decode response: %w", err)
	}
	return resp.StatusCode, nil
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func decodeStatusError(resp *http.Response) error {
	var payload struct {
		Error string `json:"error"`
	}
	// Best effort: a proxy or a crash may answer with HTML.
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&payload)
	return &StatusError{Status: resp.StatusCode, Message: payload.Error}
}

// PathEscape escapes one path segment.
func PathEscape(s string) string { return url.PathEscape(s) }
