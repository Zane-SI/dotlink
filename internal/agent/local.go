package agent

import (
	"context"
	"errors"
	"log/slog"

	"github.com/Zane-SI/dotlink/internal/control"
	"github.com/Zane-SI/dotlink/internal/ipc"
)

// LocalControl is the Agent's side of the socket: it turns the four verbs a
// menu bar needs into supervisor calls and one Control Plane request.
type LocalControl struct {
	Supervisor *Supervisor
	State      State
	// Home overrides where the status snapshot lives. Empty means this Node's
	// DOTLINK_HOME.
	Home string
	// AdminToken is what it takes to sign an Invite. A Node that is not the
	// Gateway simply has none, and says so.
	AdminToken string
	Logger     *slog.Logger
}

// Status merges the live snapshot with the enrolled identity, so a stopped
// tunnel still shows the address it will get back.
func (c *LocalControl) Status(context.Context) (ipc.Status, error) {
	st := ipc.Status{
		Running:   c.Supervisor != nil && c.Supervisor.Running(),
		Hostname:  c.State.Hostname,
		IPv4:      c.State.IPv4,
		IPv6:      c.State.IPv6,
		CanInvite: c.AdminToken != "",
		Network:   c.State.Network.Name,
	}
	if c.Supervisor != nil {
		if err := c.Supervisor.Err(); err != nil {
			st.Error = err.Error()
		}
	}
	if !st.Running {
		return st, nil
	}
	rt, err := LoadRuntimeIn(c.home())
	if err != nil {
		// Running but no snapshot yet: the session is still coming up.
		return st, nil
	}
	st.PID = rt.PID
	st.Registered = rt.Registered
	st.RelayUDP = rt.RelayUDP
	st.RelayMode = rt.RelayMode
	if rt.Hostname != "" {
		st.Hostname = rt.Hostname
	}
	if rt.IPv4 != "" {
		st.IPv4 = rt.IPv4
	}
	if rt.IPv6 != "" {
		st.IPv6 = rt.IPv6
	}
	if rt.Network != "" {
		st.Network = rt.Network
	}
	st.Peers = make([]ipc.Peer, 0, len(rt.Peers))
	for _, p := range rt.Peers {
		st.Peers = append(st.Peers, ipc.Peer{Hostname: p.Hostname, IPv4: p.IPv4, Path: p.Path, RTTms: p.RTTms})
	}
	return st, nil
}

// CreateInvite signs a QR code through the Control Plane. The Client never
// sees the admin token: it only ever sees the resulting short-lived URL.
func (c *LocalControl) CreateInvite(ctx context.Context) (ipc.Invite, error) {
	if c.AdminToken == "" {
		return ipc.Invite{}, errors.New("this Mac is not the Gateway: no admin token is configured")
	}
	if c.State.Server == "" {
		return ipc.Invite{}, errors.New("no Control Plane address: run `dotlink-agent join <link>` first")
	}
	inv, err := control.NewAdmin(c.State.Server, c.AdminToken).CreateInvite(ctx)
	if err != nil {
		return ipc.Invite{}, err
	}
	return ipc.Invite{URL: inv.URL, ExpiresAt: inv.ExpiresAt}, nil
}

// Disconnect stops the session and waits for the TUN to be gone.
func (c *LocalControl) Disconnect(context.Context) error {
	if c.Supervisor == nil {
		return errors.New("no tunnel to disconnect")
	}
	c.Supervisor.Stop()
	return nil
}

// Connect resumes the session if it is not already up.
func (c *LocalControl) Connect(ctx context.Context) error {
	if c.Supervisor == nil {
		return errors.New("no tunnel to connect")
	}
	return c.Supervisor.Start(ctx)
}

func (c *LocalControl) home() string {
	if c.Home != "" {
		return c.Home
	}
	return mustHome()
}
