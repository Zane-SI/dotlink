package ipc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeProvider struct {
	status    Status
	invite    Invite
	err       error
	connected int
}

func (f *fakeProvider) Status(context.Context) (Status, error) {
	return f.status, f.err
}

func (f *fakeProvider) CreateInvite(context.Context) (Invite, error) {
	return f.invite, f.err
}

func (f *fakeProvider) Disconnect(context.Context) error {
	f.connected = 0
	return f.err
}

func (f *fakeProvider) Connect(context.Context) error {
	f.connected = 1
	return f.err
}

// shortDir exists because macOS caps a unix socket path at 104 bytes, and
// t.TempDir() already spends most of that on the test name.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dlk")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func serve(t *testing.T, p Provider) string {
	t.Helper()
	path := filepath.Join(shortDir(t), "agent.sock")
	srv := &Server{Path: path, Provider: p, Logger: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-errc; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	// Wait for the socket to exist; ListenAndServe creates it before serving.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the socket never appeared")
	return ""
}

func TestStatusTravelsOverTheSocket(t *testing.T) {
	p := &fakeProvider{status: Status{
		Running: true, PID: 42, IPv4: "100.64.0.1", RelayMode: "derp",
		Peers: []Peer{{Hostname: "macbook", IPv4: "100.64.0.2", Path: "Direct", RTTms: 12}},
	}}
	c := NewClient(serve(t, p))
	got, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !got.Running || got.PID != 42 || got.RelayMode != "derp" {
		t.Fatalf("status = %+v", got)
	}
	if len(got.Peers) != 1 || got.Peers[0].RTTms != 12 {
		t.Fatalf("peers = %+v", got.Peers)
	}
}

func TestCreateInviteReturnsTheURL(t *testing.T) {
	want := Invite{URL: "dotlink://enroll?v=1&u=http://x&t=abc", ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
	c := NewClient(serve(t, &fakeProvider{invite: want}))
	got, err := c.CreateInvite(context.Background())
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if got.URL != want.URL || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("invite = %+v, want %+v", got, want)
	}
}

func TestProviderErrorsReachTheClient(t *testing.T) {
	c := NewClient(serve(t, &fakeProvider{err: errors.New("this Mac is not the Gateway")}))
	if _, err := c.CreateInvite(context.Background()); err == nil {
		t.Fatal("the provider's error was swallowed")
	} else if err.Error() != "this Mac is not the Gateway" {
		t.Fatalf("err = %v", err)
	}
}

func TestConnectAndDisconnectReachTheProvider(t *testing.T) {
	p := &fakeProvider{}
	c := NewClient(serve(t, p))
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if p.connected != 1 {
		t.Fatal("connect did not reach the provider")
	}
	if err := c.Disconnect(context.Background()); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if p.connected != 0 {
		t.Fatal("disconnect did not reach the provider")
	}
}

func TestTheSocketIsNotWorldWritable(t *testing.T) {
	path := serve(t, &fakeProvider{})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o660 {
		t.Fatalf("socket mode = %o, want 660", mode)
	}
}

func TestGetOnlyEndpointsRejectPosts(t *testing.T) {
	path := serve(t, &fakeProvider{})
	// A raw POST to /status must not be answered with a status: the daemon
	// has no CSRF token, so the method is the guard.
	c := NewClient(path)
	req, _ := http.NewRequest(http.MethodPost, "http://dotlink/status", nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status code = %d", resp.StatusCode)
	}
}

func TestClosingRemovesTheSocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "agent.sock")
	srv := &Server{Path: path, Provider: &fakeProvider{}, Logger: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the socket file survived Close: %v", err)
	}
}
