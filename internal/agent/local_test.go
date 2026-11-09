package agent

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Zane-SI/dotlink/internal/proto"
)

func localControl(t *testing.T, token string) (*LocalControl, *Supervisor, string) {
	t.Helper()
	sup := &Supervisor{
		Logger: slog.New(slog.DiscardHandler),
		Run: func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		},
	}
	home := t.TempDir()
	lc := &LocalControl{
		Supervisor: sup,
		Logger:     slog.New(slog.DiscardHandler),
		Home:       home,
		AdminToken: token,
		State: State{
			Server: "https://dotlink.example.com", IPv4: "100.64.0.1",
			IPv6: "fd00::1", Hostname: "mac-mini", Network: proto.Network{Name: "home", Domain: "dotlink"},
		},
	}
	return lc, sup, home
}

func TestStatusBeforeTheTunnelComesUp(t *testing.T) {
	lc, _, _ := localControl(t, "")
	st, err := lc.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Running {
		t.Fatal("status claimed a running tunnel")
	}
	// The address is still worth showing: it is how this Mac is reachable
	// once the user connects.
	if st.IPv4 != "100.64.0.1" || st.Hostname != "mac-mini" {
		t.Fatalf("status = %+v", st)
	}
	if st.CanInvite {
		t.Fatal("a Mac without an admin token claimed it could sign invites")
	}
}

func TestStatusPrefersTheLiveSnapshot(t *testing.T) {
	lc, sup, home := localControl(t, "dlk_adm_x")
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer sup.Stop()
	rt := Runtime{PID: 4242, StartedAt: time.Now(), RelayUDP: "relay:3478", RelayMode: "derp",
		Registered: true, Peers: []RuntimePeer{{Hostname: "macbook", IPv4: "100.64.0.2", Path: "Direct", RTTms: 9}}}
	if err := SaveRuntimeIn(home, rt); err != nil {
		t.Fatalf("save runtime: %v", err)
	}
	st, err := lc.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Running || st.PID != 4242 || st.RelayMode != "derp" || !st.Registered {
		t.Fatalf("status = %+v", st)
	}
	if len(st.Peers) != 1 || st.Peers[0].Path != "Direct" || st.Peers[0].RTTms != 9 {
		t.Fatalf("peers = %+v", st.Peers)
	}
	if !st.CanInvite {
		t.Fatal("an admin token did not unlock invites")
	}
}

func TestCreateInviteNeedsAnAdminToken(t *testing.T) {
	lc, _, _ := localControl(t, "")
	_, err := lc.CreateInvite(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Gateway") {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateInviteProxiesTheControlPlane(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Header.Get("Authorization") != "Bearer dlk_adm_x" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"inv_1","token":"t","url":"dotlink://enroll?v=1&u=https://x&t=t&n=home","expires_at":"2026-11-10T00:00:00Z"}`))
	}))
	defer srv.Close()
	lc, _, _ := localControl(t, "dlk_adm_x")
	lc.State.Server = srv.URL
	inv, err := lc.CreateInvite(context.Background())
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if gotPath != "/v1/admin/invites" {
		t.Fatalf("path = %s", gotPath)
	}
	if inv.URL == "" || inv.ExpiresAt.IsZero() {
		t.Fatalf("invite = %+v", inv)
	}
}

func TestDisconnectAndConnectDriveTheSupervisor(t *testing.T) {
	lc, sup, _ := localControl(t, "")
	ctx := context.Background()
	if err := lc.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !sup.Running() {
		t.Fatal("Connect did not start the tunnel")
	}
	if err := lc.Disconnect(ctx); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if sup.Running() {
		t.Fatal("Disconnect left the tunnel up")
	}
}
