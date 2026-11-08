package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zane-SI/dotlink/internal/proto"
)

const testAdminToken = "dlk_adm_test"

// fakeClock lets a test jump past an Invite's 24-hour window without sleeping.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type testEnv struct {
	*Server
	base  string
	clock *fakeClock
}

// newTestEnv starts a Control Plane on a real port backed by a real SQLite
// file, so tests observe exactly what an Agent would see.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	clock := &fakeClock{t: time.Now()}
	srv, err := Open(Config{
		DBPath:          filepath.Join(t.TempDir(), "dotlink.db"),
		AdminToken:      testAdminToken,
		PublicURL:       "https://203.0.113.7:8443",
		NetworkName:     "home",
		Domain:          "dotlink",
		LongPollTimeout: 300 * time.Millisecond,
		Now:             clock.Now,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return &testEnv{Server: srv, base: ts.URL, clock: clock}
}

// call sends a request and decodes a JSON response into out when out != nil.
func (e *testEnv) call(t *testing.T, method, path, token string, body any, out any) *http.Response {
	t.Helper()
	payload := ""
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		payload = string(b)
	}
	req, err := http.NewRequest(method, e.base+path, strings.NewReader(payload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s %s (%d): %v", method, path, resp.StatusCode, err)
		}
	}
	return resp
}

// newInvite mints an Invite through the admin API.
func (e *testEnv) newInvite(t *testing.T) proto.Invite {
	t.Helper()
	var inv proto.Invite
	resp := e.call(t, http.MethodPost, "/v1/admin/invites", testAdminToken, struct{}{}, &inv)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create invite: status = %d, want 201", resp.StatusCode)
	}
	return inv
}

// enroll redeems an Invite and returns the response plus the decoded body.
func (e *testEnv) enroll(t *testing.T, req proto.EnrollRequest) (*http.Response, proto.EnrollResponse) {
	t.Helper()
	var out proto.EnrollResponse
	resp := e.call(t, http.MethodPost, "/v1/enroll", "", req, &out)
	return resp, out
}

func TestIssueInvite(t *testing.T) {
	e := newTestEnv(t)
	inv := e.newInvite(t)

	if !strings.HasPrefix(inv.Token, "dlk_inv_") {
		t.Errorf("token = %q, want dlk_inv_ prefix", inv.Token)
	}

	u, err := url.Parse(inv.URL)
	if err != nil {
		t.Fatalf("invite url %q is not a URL: %v", inv.URL, err)
	}
	if u.Scheme != "dotlink" || u.Host != "enroll" {
		t.Errorf("url = %q, want dotlink://enroll", inv.URL)
	}
	q := u.Query()
	if q.Get("v") != "1" {
		t.Errorf("v = %q, want 1", q.Get("v"))
	}
	if got := q.Get("u"); got != "https://203.0.113.7:8443" {
		t.Errorf("u = %q, want the PublicURL", got)
	}
	if q.Get("t") != inv.Token {
		t.Errorf("t = %q, want the invite token", q.Get("t"))
	}
	if q.Get("n") != "home" {
		t.Errorf("n = %q, want the network name", q.Get("n"))
	}

	// The QR code carries no private key: the URL must not mention one.
	if strings.Contains(strings.ToLower(inv.URL), "key") {
		t.Errorf("url %q leaks key material", inv.URL)
	}

	if d := inv.ExpiresAt.Sub(e.clock.Now()); d != inviteTTL {
		t.Errorf("expires_at is %v out, want %v", d, inviteTTL)
	}
}

func TestAdminRequiresToken(t *testing.T) {
	e := newTestEnv(t)

	for _, tok := range []string{"", "wrong", "dlk_inv_something"} {
		resp := e.call(t, http.MethodGet, "/v1/admin/invites", tok, nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q: status = %d, want 401", tok, resp.StatusCode)
		}
	}
}

func TestListAndDeleteInvite(t *testing.T) {
	e := newTestEnv(t)

	first := e.newInvite(t)
	second := e.newInvite(t)

	var list struct{ Invites []proto.Invite }
	resp := e.call(t, http.MethodGet, "/v1/admin/invites", testAdminToken, nil, &list)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want 200", resp.StatusCode)
	}
	if len(list.Invites) != 2 {
		t.Fatalf("got %d invites, want 2", len(list.Invites))
	}
	for _, inv := range list.Invites {
		if inv.UsedBy != "" {
			t.Errorf("invite %s already shows used_by=%q", inv.ID, inv.UsedBy)
		}
	}

	if resp := e.call(t, http.MethodDelete, "/v1/admin/invites/"+first.ID, testAdminToken, nil, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", resp.StatusCode)
	}

	list.Invites = nil
	e.call(t, http.MethodGet, "/v1/admin/invites", testAdminToken, nil, &list)
	if len(list.Invites) != 1 || list.Invites[0].ID != second.ID {
		t.Fatalf("after delete, invites = %+v, want only %s", list.Invites, second.ID)
	}

	if resp := e.call(t, http.MethodDelete, "/v1/admin/invites/"+first.ID, testAdminToken, nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", resp.StatusCode)
	}
}

func TestEnroll(t *testing.T) {
	e := newTestEnv(t)
	inv := e.newInvite(t)

	resp, got := e.enroll(t, proto.EnrollRequest{
		Invite:   inv.Token,
		Pubkey:   "pubkey-of-mac-mini",
		Hostname: "mac-mini",
		OS:       "darwin",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if !strings.HasPrefix(got.NodeID, "n_") {
		t.Errorf("node_id = %q, want n_ prefix", got.NodeID)
	}
	if !strings.HasPrefix(got.NodeToken, "dlk_nt_") {
		t.Errorf("node_token = %q, want dlk_nt_ prefix", got.NodeToken)
	}
	if got.IPv4 != "100.64.0.1" {
		t.Errorf("ipv4 = %q, want the first address in the pool", got.IPv4)
	}
	if got.IPv6 != "fd00::1" {
		t.Errorf("ipv6 = %q, want the first address in the pool", got.IPv6)
	}
	if got.Network.Name != "home" || got.Network.Domain != "dotlink" {
		t.Errorf("network = %+v, want home/dotlink", got.Network)
	}

	// The Invite is spent: it now names the Node that redeemed it.
	var list struct{ Invites []proto.Invite }
	e.call(t, http.MethodGet, "/v1/admin/invites", testAdminToken, nil, &list)
	if len(list.Invites) != 1 || list.Invites[0].UsedBy != got.NodeID {
		t.Fatalf("invites = %+v, want one with used_by=%s", list.Invites, got.NodeID)
	}

	// The second Node must not collide with the first.
	inv2 := e.newInvite(t)
	_, second := e.enroll(t, proto.EnrollRequest{Invite: inv2.Token, Pubkey: "pk2", Hostname: "macbook", OS: "darwin"})
	if second.IPv4 != "100.64.0.2" || second.IPv6 != "fd00::2" {
		t.Errorf("second node got %s/%s, want 100.64.0.2/fd00::2", second.IPv4, second.IPv6)
	}
	if second.NodeID == got.NodeID {
		t.Errorf("two nodes share node_id %s", got.NodeID)
	}
}

func TestEnrollRejectsBadInvite(t *testing.T) {
	e := newTestEnv(t)

	if resp, _ := e.enroll(t, proto.EnrollRequest{Invite: "dlk_inv_nope", Pubkey: "pk", Hostname: "x", OS: "linux"}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown invite: status = %d, want 404", resp.StatusCode)
	}

	inv := e.newInvite(t)
	e.enroll(t, proto.EnrollRequest{Invite: inv.Token, Pubkey: "pk", Hostname: "x", OS: "linux"})

	if resp, _ := e.enroll(t, proto.EnrollRequest{Invite: inv.Token, Pubkey: "pk2", Hostname: "y", OS: "linux"}); resp.StatusCode != http.StatusConflict {
		t.Errorf("reused invite: status = %d, want 409", resp.StatusCode)
	}
}

func TestEnrollRejectsExpiredInvite(t *testing.T) {
	e := newTestEnv(t)
	inv := e.newInvite(t)

	e.clock.Advance(25 * time.Hour)
	if resp, _ := e.enroll(t, proto.EnrollRequest{Invite: inv.Token, Pubkey: "pk", Hostname: "x", OS: "linux"}); resp.StatusCode != http.StatusGone {
		t.Errorf("expired invite: status = %d, want 410", resp.StatusCode)
	}
}

// joinNode mints an Invite and enrolls a Node in one step.
func (e *testEnv) joinNode(t *testing.T, hostname string) proto.EnrollResponse {
	t.Helper()
	inv := e.newInvite(t)
	resp, node := e.enroll(t, proto.EnrollRequest{
		Invite: inv.Token, Pubkey: "pk-" + hostname, Hostname: hostname, OS: "darwin",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll %s: status = %d", hostname, resp.StatusCode)
	}
	return node
}

func TestMapShowsSelfAndPeers(t *testing.T) {
	e := newTestEnv(t)
	mini := e.joinNode(t, "mac-mini")
	book := e.joinNode(t, "macbook")

	var pm proto.PeerMap
	resp := e.call(t, http.MethodGet, "/v1/map?since=0", mini.NodeToken, nil, &pm)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if pm.Self.NodeID != mini.NodeID || pm.Self.Hostname != "mac-mini" {
		t.Errorf("self = %+v, want mac-mini", pm.Self)
	}
	if pm.Self.IPv4 != mini.IPv4 || pm.Self.IPv6 != mini.IPv6 {
		t.Errorf("self addresses = %s/%s, want %s/%s", pm.Self.IPv4, pm.Self.IPv6, mini.IPv4, mini.IPv6)
	}
	if len(pm.Peers) != 1 {
		t.Fatalf("got %d peers, want only macbook", len(pm.Peers))
	}
	peer := pm.Peers[0]
	if peer.NodeID != book.NodeID || peer.Hostname != "macbook" {
		t.Errorf("peer = %+v, want macbook", peer)
	}
	if peer.Pubkey != "pk-macbook" {
		t.Errorf("peer pubkey = %q, want the one it enrolled with", peer.Pubkey)
	}
	if !peer.Online {
		t.Errorf("peer is offline right after enrolling")
	}
	if pm.Version == 0 {
		t.Errorf("version = 0, want a bumped version")
	}
}

func TestMapLongPollTimesOut(t *testing.T) {
	e := newTestEnv(t)
	mini := e.joinNode(t, "mac-mini")
	version := e.currentVersion()

	start := time.Now()
	resp := e.call(t, http.MethodGet, "/v1/map?since="+strconv.FormatInt(version, 10), mini.NodeToken, nil, nil)
	elapsed := time.Since(start)

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if elapsed < 250*time.Millisecond {
		t.Errorf("returned after %v, want it to hang for the full LongPollTimeout", elapsed)
	}
}

func TestMapLongPollWakesOnEnroll(t *testing.T) {
	e := newTestEnv(t)
	mini := e.joinNode(t, "mac-mini")
	version := e.currentVersion()

	type result struct {
		pm     proto.PeerMap
		status int
	}
	done := make(chan result, 1)
	go func() {
		var pm proto.PeerMap
		resp := e.call(t, http.MethodGet, "/v1/map?since="+strconv.FormatInt(version, 10), mini.NodeToken, nil, &pm)
		done <- result{pm: pm, status: resp.StatusCode}
	}()

	// Give the poll a moment to park, then make the map change.
	time.Sleep(50 * time.Millisecond)
	e.joinNode(t, "macbook")

	select {
	case got := <-done:
		if got.status != http.StatusOK {
			t.Fatalf("status = %d, want 200 after the map changed", got.status)
		}
		if len(got.pm.Peers) != 1 || got.pm.Peers[0].Hostname != "macbook" {
			t.Fatalf("peers = %+v, want the newly enrolled macbook", got.pm.Peers)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long poll never woke up after a Node enrolled")
	}
}

func TestMapRejectsUnknownOrRevokedNode(t *testing.T) {
	e := newTestEnv(t)
	mini := e.joinNode(t, "mac-mini")

	if resp := e.call(t, http.MethodGet, "/v1/map?since=0", "", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", resp.StatusCode)
	}
	if resp := e.call(t, http.MethodGet, "/v1/map?since=0", "dlk_nt_bogus", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bogus token: status = %d, want 401", resp.StatusCode)
	}

	if resp := e.call(t, http.MethodDelete, "/v1/admin/nodes/"+mini.NodeID, testAdminToken, nil, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: status = %d, want 204", resp.StatusCode)
	}
	if resp := e.call(t, http.MethodGet, "/v1/map?since=0", mini.NodeToken, nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked token: status = %d, want 401", resp.StatusCode)
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dotlink.db")
	clock := &fakeClock{t: time.Now()}
	cfg := Config{
		DBPath: path, AdminToken: testAdminToken,
		PublicURL: "https://203.0.113.7:8443", NetworkName: "home", Domain: "dotlink",
		LongPollTimeout: 300 * time.Millisecond, Now: clock.Now,
	}

	first, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ts := httptest.NewServer(first)
	e := &testEnv{Server: first, base: ts.URL, clock: clock}

	mini := e.joinNode(t, "mac-mini")
	version := first.currentVersion()
	ts.Close()
	first.Close()

	// A restart must not lose the Node, its token, or the map version.
	second, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()
	ts2 := httptest.NewServer(second)
	defer ts2.Close()

	e2 := &testEnv{Server: second, base: ts2.URL, clock: clock}
	if got := second.currentVersion(); got != version {
		t.Errorf("version after restart = %d, want %d", got, version)
	}

	var pm proto.PeerMap
	resp := e2.call(t, http.MethodGet, "/v1/map?since=0", mini.NodeToken, nil, &pm)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("map after restart: status = %d, want 200", resp.StatusCode)
	}
	if pm.Self.NodeID != mini.NodeID || pm.Self.IPv4 != "100.64.0.1" {
		t.Errorf("self after restart = %+v, want the enrolled mac-mini", pm.Self)
	}

	// Address allocation must continue where it left off, not hand out .1 twice.
	inv := e2.newInvite(t)
	_, book := e2.enroll(t, proto.EnrollRequest{Invite: inv.Token, Pubkey: "pk", Hostname: "macbook", OS: "darwin"})
	if book.IPv4 != "100.64.0.2" {
		t.Errorf("next address after restart = %s, want 100.64.0.2", book.IPv4)
	}
}
