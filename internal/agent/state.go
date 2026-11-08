// Package agent is the client side of the Control Plane: it enrolls a Node,
// remembers its identity on disk, and reads the Peer Map.
package agent

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Zane-SI/dotlink/internal/proto"
)

// State is what a Node remembers between runs. The private key never leaves
// this file: the Control Plane only ever sees the public half.
type State struct {
	Server    string        `json:"server"`
	NodeID    string        `json:"node_id"`
	NodeToken string        `json:"node_token"`
	IPv4      string        `json:"ipv4"`
	IPv6      string        `json:"ipv6"`
	Hostname  string        `json:"hostname"`
	PrivKey   string        `json:"privkey"`
	Network   proto.Network `json:"network"`
	Version   int64         `json:"map_version"`
}

// Home is the directory holding the Node's state. DOTLINK_HOME overrides it so
// tests and the integration suite never touch a real install.
func Home() (string, error) {
	if h := os.Getenv("DOTLINK_HOME"); h != "" {
		return h, nil
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(dir, ".dotlink"), nil
}

// StatePath is where State lives: $DOTLINK_HOME/node.json.
func StatePath() (string, error) {
	home, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "node.json"), nil
}

// LoadState reads the saved identity.
func LoadState() (State, error) {
	path, err := StatePath()
	if err != nil {
		return State{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, fmt.Errorf("this machine is not enrolled yet: run `dotlink-agent join <url>` first")
		}
		return State{}, fmt.Errorf("read %s: %w", path, err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return st, nil
}

// SaveState writes the identity with 0600: the file holds a private key.
func SaveState(st State) error {
	path, err := StatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// EnrollLink is the parsed form of the dotlink:// URL that a QR code carries.
type EnrollLink struct {
	Server  string
	Invite  string
	Network string
}

// ParseEnrollLink reads dotlink://enroll?v=1&u=...&t=...&n=...
func ParseEnrollLink(raw string) (EnrollLink, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return EnrollLink{}, fmt.Errorf("parse %q: %w", raw, err)
	}
	if u.Scheme != "dotlink" || u.Host != "enroll" {
		return EnrollLink{}, fmt.Errorf("%q is not a Dotlink enroll link (want dotlink://enroll?...)", raw)
	}
	q := u.Query()
	if q.Get("v") != "1" {
		return EnrollLink{}, fmt.Errorf("unsupported link version %q", q.Get("v"))
	}
	link := EnrollLink{Server: q.Get("u"), Invite: q.Get("t"), Network: q.Get("n")}
	if link.Server == "" || link.Invite == "" {
		return EnrollLink{}, fmt.Errorf("enroll link is missing the server or invite token")
	}
	return link, nil
}

// GenerateKey makes the Node's Curve25519 identity. The private key stays here;
// only PubKeyBase64 goes over the wire.
func GenerateKey() (privBase64, pubBase64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// NormalizeServer accepts "host:port" or "https://host:port" and returns a URL
// without a trailing slash.
func NormalizeServer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty server address")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse server %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("server %q has no host", raw)
	}
	return strings.TrimSuffix(u.Scheme+"://"+u.Host, "/"), nil
}
