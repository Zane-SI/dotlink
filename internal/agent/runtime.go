package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Runtime is what `dotlink-agent status` reads. It is a snapshot the daemon
// rewrites, not a control channel: nothing here is authoritative, and a stale
// file after a crash is corrected by the next start.
type Runtime struct {
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	// The Node's own identity, so a Client can draw the status without a
	// second call to the Control Plane.
	Hostname string `json:"hostname,omitempty"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	Network  string `json:"network,omitempty"`

	RelayUDP string `json:"relay_udp"`
	// RelayMode is "udp" or "derp": which transport relayed traffic uses.
	RelayMode string `json:"relay_mode,omitempty"`
	// AdvertiseRoutes are the LANs this Node forwards for; empty for an
	// ordinary Node.
	AdvertiseRoutes []string      `json:"advertise_routes,omitempty"`
	Registered      bool          `json:"registered"`
	Peers           []RuntimePeer `json:"peers"`
}

// RuntimePeer is one Node as this Agent currently reaches it.
type RuntimePeer struct {
	Hostname string `json:"hostname"`
	IPv4     string `json:"ipv4"`
	Path     string `json:"path"`             // Relayed until a punch lands, then Direct
	RTTms    int64  `json:"rtt_ms,omitempty"` // only meaningful on a direct path
}

// RuntimePath is where the daemon leaves its snapshot.
func RuntimePath() string {
	home, err := Home()
	if err != nil {
		return "runtime.json"
	}
	return filepath.Join(home, "runtime.json")
}

// RuntimePathIn is RuntimePath for an explicit home, which is what a test (or
// a user running two Nodes on one machine) needs.
func RuntimePathIn(home string) string { return filepath.Join(home, "runtime.json") }

// LoadRuntime reads the daemon's snapshot.
func LoadRuntime() (Runtime, error) {
	home, err := Home()
	if err != nil {
		return Runtime{}, err
	}
	return LoadRuntimeIn(home)
}

// LoadRuntimeIn reads the snapshot in an explicit home.
func LoadRuntimeIn(home string) (Runtime, error) {
	var rt Runtime
	raw, err := os.ReadFile(RuntimePathIn(home))
	if err != nil {
		return rt, err
	}
	if err := json.Unmarshal(raw, &rt); err != nil {
		return rt, fmt.Errorf("read %s: %w", RuntimePathIn(home), err)
	}
	return rt, nil
}

// SaveRuntime replaces the snapshot in this Node's home.
func SaveRuntime(rt Runtime) error {
	home, err := Home()
	if err != nil {
		return err
	}
	return SaveRuntimeIn(home, rt)
}

// SaveRuntimeIn replaces the snapshot atomically, so a reader never sees half
// a file even if the daemon is killed mid-write.
func SaveRuntimeIn(home string, rt Runtime) error {
	raw, err := json.MarshalIndent(rt, "", "  ")
	if err != nil {
		return fmt.Errorf("encode runtime: %w", err)
	}
	path := RuntimePathIn(home)
	tmp, err := os.CreateTemp(home, "runtime-*.json")
	if err != nil {
		return fmt.Errorf("write runtime: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("write runtime: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write runtime: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("write runtime: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write runtime: %w", err)
	}
	return nil
}

// RemoveRuntime deletes the snapshot on a clean shutdown.
func RemoveRuntime() error { return RemoveRuntimeIn(mustHome()) }

func mustHome() string {
	home, err := Home()
	if err != nil {
		return "."
	}
	return home
}

// RemoveRuntimeIn deletes the snapshot in an explicit home.
func RemoveRuntimeIn(home string) error {
	err := os.Remove(RuntimePathIn(home))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
