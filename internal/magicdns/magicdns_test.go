package magicdns

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func testServer(records map[string]Record) *Server {
	return &Server{
		Zone:   "dotlink",
		Lookup: func() map[string]Record { return records },
		Log:    slog.New(slog.DiscardHandler),
	}
}

// query builds a minimal DNS question, the way a stub resolver would.
func query(name string, qtype uint16) []byte {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range split(name) {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, classIN)
	return b
}

func split(name string) []string {
	var out []string
	cur := ""
	for _, r := range name {
		if r == '.' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func rcode(resp []byte) uint8 { return resp[3] & 0x0f }

func answerIPs(t *testing.T, resp []byte) []string {
	t.Helper()
	an := binary.BigEndian.Uint16(resp[6:8])
	// Skip the header and the echoed question to reach the answers.
	_, off := readNameOffset(resp)
	off += 4
	var out []string
	for i := 0; i < int(an); i++ {
		// Each answer starts with a compression pointer to the question name.
		off += 2
		if off+12 > len(resp) {
			t.Fatalf("answer %d runs past the packet", i)
		}
		typ := binary.BigEndian.Uint16(resp[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
		rdata := resp[off+10 : off+10+rdlen]
		switch typ {
		case typeA:
			out = append(out, net.IP(rdata).String())
		case typeAAAA:
			out = append(out, net.IP(rdata).String())
		}
		off += 10 + rdlen
	}
	return out
}

func readNameOffset(b []byte) (string, int) {
	name, off, err := readName(b, 12)
	if err != nil {
		panic(err)
	}
	return name, off
}

func TestAnswersAAndAAAA(t *testing.T) {
	s := testServer(map[string]Record{
		"mac-mini": {IPv4: netip.MustParseAddr("100.64.0.1"), IPv6: netip.MustParseAddr("fd00::1")},
	})
	for _, tc := range []struct {
		qtype uint16
		want  string
	}{
		{typeA, "100.64.0.1"},
		{typeAAAA, "fd00::1"},
	} {
		resp := s.Answer(query("mac-mini.dotlink", tc.qtype))
		if resp == nil {
			t.Fatalf("type %d: no response", tc.qtype)
		}
		if rcode(resp) != rcodeNoError {
			t.Fatalf("type %d: rcode %d", tc.qtype, rcode(resp))
		}
		got := answerIPs(t, resp)
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("type %d: answers %v, want %s", tc.qtype, got, tc.want)
		}
	}
}

func TestNameMatchingIsForgiving(t *testing.T) {
	s := testServer(map[string]Record{"mac-mini": {IPv4: netip.MustParseAddr("100.64.0.1")}})
	for _, name := range []string{"mac-mini.dotlink", "MAC-Mini.DotLink.", "mac-mini.dotlink."} {
		resp := s.Answer(query(name, typeA))
		if got := answerIPs(t, resp); len(got) != 1 {
			t.Fatalf("%q: answers %v", name, got)
		}
	}
}

func TestRevokedNodeIsNXDomainNotTimeout(t *testing.T) {
	records := map[string]Record{"mac-mini": {IPv4: netip.MustParseAddr("100.64.0.1")}}
	s := testServer(records)
	if rcode(s.Answer(query("mac-mini.dotlink", typeA))) != rcodeNoError {
		t.Fatal("the node did not resolve before revocation")
	}
	delete(records, "mac-mini")
	resp := s.Answer(query("mac-mini.dotlink", typeA))
	if resp == nil {
		t.Fatal("no response; a stub resolver would wait for a timeout")
	}
	if rcode(resp) != rcodeNXDomain {
		t.Fatalf("rcode = %d, want NXDOMAIN", rcode(resp))
	}
}

func TestForeignNamesAreRefusedNotHijacked(t *testing.T) {
	s := testServer(nil)
	resp := s.Answer(query("example.com", typeA))
	if resp == nil {
		t.Fatal("no response")
	}
	if rcode(resp) != rcodeRefused {
		t.Fatalf("rcode = %d, want REFUSED", rcode(resp))
	}
	if an := binary.BigEndian.Uint16(resp[6:8]); an != 0 {
		t.Fatalf("answers = %d, want 0", an)
	}
}

func TestDeepNamesUnderTheZoneAreNXDomain(t *testing.T) {
	s := testServer(map[string]Record{"mac-mini": {IPv4: netip.MustParseAddr("100.64.0.1")}})
	if got := rcode(s.Answer(query("a.mac-mini.dotlink", typeA))); got != rcodeNXDomain {
		t.Fatalf("rcode = %d", got)
	}
}

func TestUnknownTypeIsNoDataNotNoSuchName(t *testing.T) {
	s := testServer(map[string]Record{"mac-mini": {IPv4: netip.MustParseAddr("100.64.0.1")}})
	resp := s.Answer(query("mac-mini.dotlink", 65 /* HTTPS RR */))
	if got := rcode(resp); got != rcodeNoError {
		t.Fatalf("rcode = %d, want NOERROR", got)
	}
	if an := binary.BigEndian.Uint16(resp[6:8]); an != 0 {
		t.Fatalf("answers = %d, want 0", an)
	}
}

func TestANodeWithoutIPv6DoesNotAnswerAAAA(t *testing.T) {
	s := testServer(map[string]Record{"mac-mini": {IPv4: netip.MustParseAddr("100.64.0.1")}})
	resp := s.Answer(query("mac-mini.dotlink", typeAAAA))
	if an := binary.BigEndian.Uint16(resp[6:8]); an != 0 {
		t.Fatalf("answers = %d, want 0", an)
	}
}

func TestGarbageIsDropped(t *testing.T) {
	s := testServer(nil)
	for _, bad := range [][]byte{
		nil, {1, 2, 3}, // short header
		append(query("x.dotlink", typeA), 0, 0), // trailing junk is fine, header intact
	} {
		_ = s.Answer(bad) // must not panic
	}
	// A response packet must not be answered: that would be a reflection loop.
	resp := query("mac-mini.dotlink", typeA)
	resp[2] |= 0x80
	if got := s.Answer(resp); got != nil {
		t.Fatalf("answered a response: %v", got)
	}
}

func TestServesOverUDP(t *testing.T) {
	s := testServer(map[string]Record{"mac-mini": {IPv4: netip.MustParseAddr("100.64.0.1")}})
	s.Local = "127.0.0.1"
	s.Port = 0
	// Port 0 means "default 53" in addr(); bind an explicit free port instead.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	s.Port = port

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.ListenAndServe(ctx) }()

	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	var resp []byte
	for time.Now().Before(deadline) {
		if _, err := conn.Write(query("mac-mini.dotlink", typeA)); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err == nil {
			resp = buf[:n]
			break
		}
	}
	if resp == nil {
		t.Fatal("no answer over UDP")
	}
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != "100.64.0.1" {
		t.Fatalf("answers = %v", got)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

func TestLabel(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"mac-mini", "mac-mini"},
		{"Mac-mini.local", "mac-mini"},
		{"Zane 的 MacBook Pro", "zane-macbook-pro"},
		{"--weird--", "weird"},
		{"", "node"},
		{"...", "node"},
	} {
		if got := Label(tc.in); got != tc.want {
			t.Fatalf("Label(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := Label("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); len(got) > 63 {
		t.Fatalf("label too long: %d", len(got))
	}
}
