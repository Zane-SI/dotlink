// Package integration drives the real binaries the way a person would: a
// Control Plane on a real port, two Nodes enrolling over the wire, and one of
// them watching the Peer Map for the other to appear.
package integration_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const adminToken = "dlk_adm_e2e"

type harness struct {
	t          *testing.T
	serverBin  string
	agentBin   string
	serverURL  string
	env        []string
	serverProc *exec.Cmd
}

// newHarness builds both binaries and starts a Control Plane on a free port.
func newHarness(t *testing.T) *harness {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	binDir := t.TempDir()

	build := func(pkg, name string) string {
		out := filepath.Join(binDir, name)
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Dir = root
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", pkg, err, b)
		}
		return out
	}

	h := &harness{
		t:         t,
		serverBin: build("./cmd/dotlink-server", "dotlink-server"),
		agentBin:  build("./cmd/dotlink-agent", "dotlink-agent"),
		env:       append(os.Environ(), "DOTLINK_HOME="+t.TempDir()),
	}

	port := freePort(t)
	h.serverURL = fmt.Sprintf("http://127.0.0.1:%d", port)

	cmd := exec.Command(h.serverBin, "control",
		"--db", filepath.Join(t.TempDir(), "dotlink.db"),
		"--addr", fmt.Sprintf("127.0.0.1:%d", port),
		"--network", "home",
		"--admin-token", adminToken,
	)
	cmd.Env = h.env
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start control plane: %v", err)
	}
	h.serverProc = cmd
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	h.waitHealthy()
	return h
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func (h *harness) waitHealthy() {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(h.serverURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.t.Fatal("control plane never answered /healthz")
}

// run executes a binary and returns its combined output, failing on error.
func (h *harness) run(bin string, args ...string) string {
	h.t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = h.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("%s %s: %v\n%s", filepath.Base(bin), strings.Join(args, " "), err, out)
	}
	return string(out)
}

// invite mints an Invite and returns the enroll link printed by the CLI.
func (h *harness) invite() string {
	h.t.Helper()
	out := h.run(h.serverBin, "invite", "--server", h.serverURL, "--admin-token", adminToken)
	link := fieldAfter(out, "enroll link:")
	if link == "" {
		h.t.Fatalf("invite output has no enroll link:\n%s", out)
	}
	return link
}

// fieldAfter returns the rest of the line that starts with prefix.
func fieldAfter(out, prefix string) string {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), prefix); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func TestTwoNodesMeetThroughTheCLI(t *testing.T) {
	h := newHarness(t)

	// First Node: the one that will sit at home.
	miniOut := h.run(h.agentBin, "join", h.invite(), "--hostname", "mac-mini")
	if !strings.Contains(miniOut, "100.64.0.1") {
		t.Fatalf("join did not print the first overlay address:\n%s", miniOut)
	}
	if !strings.Contains(miniOut, "no peers yet") {
		t.Fatalf("the first Node should have no peers yet:\n%s", miniOut)
	}

	// Second Node enrolls from a different DOTLINK_HOME, so it is a separate
	// machine as far as the state files are concerned.
	bookHome := t.TempDir()
	bookEnv := append(os.Environ(), "DOTLINK_HOME="+bookHome)
	joinBook := exec.Command(h.agentBin, "join", h.invite(), "--hostname", "macbook")
	joinBook.Env = bookEnv
	if out, err := joinBook.CombinedOutput(); err != nil {
		t.Fatalf("join macbook: %v\n%s", err, out)
	}

	// The first Node must see it without anyone asking again: the long poll
	// wakes on the enrollment.
	out := h.run(h.agentBin, "peers")
	if !strings.Contains(out, "macbook") {
		t.Fatalf("mac-mini does not see macbook:\n%s", out)
	}
}

func TestPeersWatchWakesUpWhenANodeJoins(t *testing.T) {
	h := newHarness(t)
	h.run(h.agentBin, "join", h.invite(), "--hostname", "mac-mini")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	watch := exec.CommandContext(ctx, h.agentBin, "peers", "--watch")
	watch.Env = h.env
	stdout, err := watch.StdoutPipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	watch.Stderr = os.Stderr
	if err := watch.Start(); err != nil {
		t.Fatalf("start peers --watch: %v", err)
	}
	defer func() { watch.Process.Kill(); watch.Wait() }()

	// Give the watch a moment to park on its first long poll.
	time.Sleep(300 * time.Millisecond)

	bookHome := t.TempDir()
	joinBook := exec.Command(h.agentBin, "join", h.invite(), "--hostname", "macbook")
	joinBook.Env = append(os.Environ(), "DOTLINK_HOME="+bookHome)
	if out, err := joinBook.CombinedOutput(); err != nil {
		t.Fatalf("join macbook: %v\n%s", err, out)
	}

	scanner := bufio.NewScanner(stdout)
	found := make(chan string, 1)
	go func() {
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "macbook") {
				found <- scanner.Text()
				return
			}
		}
		close(found)
	}()

	select {
	case line, ok := <-found:
		if !ok {
			t.Fatal("peers --watch exited before macbook appeared")
		}
		t.Logf("watch reported: %s", line)
	case <-time.After(20 * time.Second):
		t.Fatal("peers --watch never reported macbook")
	}
}
