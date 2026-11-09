package agent

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition never became true")
}

func TestStopWaitsForTheSessionToComeDown(t *testing.T) {
	var cleaned atomic.Bool
	sup := &Supervisor{
		Logger: slog.New(slog.DiscardHandler),
		Run: func(ctx context.Context) error {
			<-ctx.Done()
			cleaned.Store(true)
			return nil
		},
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !sup.Running() {
		t.Fatal("Start did not mark the session running")
	}
	sup.Stop()
	if sup.Running() {
		t.Fatal("Stop returned with the session still running")
	}
	// Stop is the disconnect path: it must not return before the TUN is gone.
	if !cleaned.Load() {
		t.Fatal("Stop did not wait for the session to clean up")
	}
}

func TestASessionThatFailsIsRestarted(t *testing.T) {
	var runs atomic.Int32
	sup := &Supervisor{
		Logger:       slog.New(slog.DiscardHandler),
		RestartDelay: 10 * time.Millisecond,
		Run: func(ctx context.Context) error {
			if runs.Add(1) == 1 {
				return errors.New("relay refused the handshake")
			}
			<-ctx.Done()
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sup.Serve(ctx)
	waitFor(t, func() bool { return runs.Load() >= 2 && sup.Running() })
	cancel()
}

// TestSupervisorDoesNotRestartAPermanentError: a rejected advertisement or a
// missing LAN will fail the same way until the user fixes it. Restarting every
// two seconds hides the error behind a loop; staying down (until an explicit
// Connect) is the behavior the operator can act on.
func TestSupervisorDoesNotRestartAPermanentError(t *testing.T) {
	var runs atomic.Int32
	sup := &Supervisor{
		Logger:       slog.New(slog.DiscardHandler),
		RestartDelay: 10 * time.Millisecond,
		Run: func(ctx context.Context) error {
			if runs.Add(1) == 1 {
				return permanent(errors.New("route conflict"))
			}
			<-ctx.Done()
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sup.Serve(ctx)

	waitFor(t, func() bool { return runs.Load() == 1 && !sup.Running() })
	time.Sleep(80 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("the supervisor retried a permanent error %d times", got)
	}
	if sup.Running() {
		t.Fatal("the supervisor restarted a permanent error")
	}

	// Connect must still work: fixing the conflict and reconnecting is the
	// documented recovery path.
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("explicit start after a permanent error: %v", err)
	}
	if !sup.Running() {
		t.Fatal("an explicit Start did not bring the session back")
	}
}

func TestADisconnectIsNotUndoneByTheSupervisor(t *testing.T) {
	sup := &Supervisor{
		Logger:       slog.New(slog.DiscardHandler),
		RestartDelay: 10 * time.Millisecond,
		Run: func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sup.Serve(ctx)
	waitFor(t, sup.Running)
	sup.Stop()
	// The user turned the tunnel off. If Serve treated that as a crash, the
	// tunnel would silently come back and the button would lie.
	time.Sleep(80 * time.Millisecond)
	if sup.Running() {
		t.Fatal("the supervisor resurrected a session the user stopped")
	}
}

func TestConnectAfterDisconnectWorks(t *testing.T) {
	sup := &Supervisor{
		Logger: slog.New(slog.DiscardHandler),
		Run: func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		},
	}
	ctx := context.Background()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	sup.Stop()
	if err := sup.Start(ctx); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if !sup.Running() {
		t.Fatal("a second Start did not bring the session back")
	}
	sup.Stop()
}
