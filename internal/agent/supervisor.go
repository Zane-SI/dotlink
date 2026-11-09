package agent

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Supervisor keeps one tunnel session alive and lets a local Client stop and
// start it without touching launchd.
//
// The distinction matters: the launch daemon must survive a disconnect (or
// KeepAlive would immediately resurrect the tunnel the user just turned off)
// but must also survive a crash (or a bug would leave the machine offline).
// So the process stays, the session comes and goes.
type Supervisor struct {
	// Run is one session. It must return when its context is cancelled.
	Run func(context.Context) error
	// RestartDelay is how long to wait before retrying a session that failed
	// on its own. Zero means two seconds.
	RestartDelay time.Duration
	Logger       *slog.Logger

	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	running bool
	lastErr error
}

const defaultRestartDelay = 2 * time.Second

// Start brings the tunnel up. It is a no-op when already running.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}
	run := s.Run
	if run == nil {
		return errors.New("supervisor has nothing to run")
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.cancel, s.done, s.running, s.lastErr = cancel, done, true, nil
	go func() {
		err := run(sessionCtx)
		s.mu.Lock()
		// A session that returned because we cancelled it is a clean stop,
		// not a failure to report.
		if sessionCtx.Err() == nil {
			s.lastErr = err
		}
		s.running = false
		s.mu.Unlock()
		close(done)
		cancel()
	}()
	return nil
}

// Stop tears the session down and waits for the TUN and routes to be gone.
// Waiting is the point: `disconnect` returning before the interface is gone
// would make the next command lie.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	running := s.running
	s.mu.Unlock()
	if !running || cancel == nil {
		return
	}
	cancel()
	<-done
}

// Running reports whether a session is up.
func (s *Supervisor) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Err is the last session failure, cleared when a session is started.
func (s *Supervisor) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// Serve runs the session until ctx is cancelled, restarting it after a crash.
// A deliberate Stop is respected: Serve does not resurrect a session the user
// turned off.
func (s *Supervisor) Serve(ctx context.Context) {
	log := s.Logger
	if log == nil {
		log = slog.Default()
	}
	delay := s.RestartDelay
	if delay <= 0 {
		delay = defaultRestartDelay
	}
	if err := s.Start(ctx); err != nil {
		log.Error("start tunnel", "err", err)
	}
	// A failed session is retried silently otherwise, which turns a 409 on the
	// route advertisement (or a missing LAN) into an invisible restart loop.
	var loggedErr error
	for {
		select {
		case <-ctx.Done():
			s.Stop()
			return
		default:
		}
		s.mu.Lock()
		running, done := s.running, s.done
		s.mu.Unlock()
		if running {
			select {
			case <-done:
				continue
			case <-ctx.Done():
				s.Stop()
				return
			}
		}
		// Idle: either the user disconnected or the session failed. Wait for
		// an explicit Connect, or retry a failure after a pause.
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
			err := s.Err()
			if err == nil {
				// Stopped on purpose; stay idle until Connect. The next
				// failure is a new event, even if it has the same text as one
				// logged before this clean run.
				loggedErr = nil
				continue
			}
			if loggedErr == nil || err.Error() != loggedErr.Error() {
				if isPermanent(err) {
					log.Error("tunnel session failed; not retrying until reconnect", "err", err)
				} else {
					log.Error("tunnel session failed", "err", err)
				}
				loggedErr = err
			}
			if isPermanent(err) {
				// Retrying a rejected advertisement or a missing LAN only hides
				// the problem behind a restart loop. Stay down until the user
				// fixes it and reconnects; Start still works then.
				continue
			}
			if err := s.Start(ctx); err != nil {
				log.Error("restart tunnel", "err", err)
			}
		}
	}
}
