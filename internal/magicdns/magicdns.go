// Package magicdns is the split-horizon resolver the Agent runs on its own
// Overlay IP. It answers <node>.dotlink with the Node's Overlay address and
// nothing else: the OS is told to send only .dotlink here, so no query for
// any other name ever reaches this code.
package magicdns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
)

// Record is one Node's answer to a name.
type Record struct {
	IPv4 netip.Addr
	IPv6 netip.Addr
}

// Server answers DNS over UDP for a single zone.
type Server struct {
	// Zone is the pseudo-TLD, "dotlink" for this project. Stored without a
	// leading dot; matching is case-insensitive and accepts a trailing dot.
	Zone string
	// Lookup returns the current records, keyed by the label under Zone.
	// It is called per query, so a revoked Node stops resolving on the next
	// question rather than on the next reconnect.
	Lookup func() map[string]Record
	// Addr is the IP to bind. Port is separate because 53 is privileged and
	// tests are not root.
	Addr  netip.Addr
	Port  int
	Local string // tests may bind loopback instead of an Overlay address
	TTL   uint32
	Log   *slog.Logger

	mu  sync.Mutex
	pc  net.PacketConn
	err error
}

// addr is what we bind: the Overlay address in production, an override in tests.
func (s *Server) addr() string {
	host := s.Local
	if host == "" {
		host = s.Addr.String()
	}
	port := s.Port
	if port == 0 {
		port = 53
	}
	return net.JoinHostPort(host, fmt.Sprint(port))
}

// ListenAndServe binds and answers until ctx is cancelled.
func (s *Server) ListenAndServe(ctx interface{ Done() <-chan struct{} }) error {
	pc, err := net.ListenPacket("udp", s.addr())
	if err != nil {
		return fmt.Errorf("magicdns: listen %s: %w", s.addr(), err)
	}
	s.mu.Lock()
	s.pc = pc
	s.mu.Unlock()
	defer pc.Close()

	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	s.log().Info("magicdns answering", "addr", pc.LocalAddr().String(), "zone", s.Zone)

	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			// A UDP read error is transient (ICMP from a client that went
			// away); dropping the socket over it would stop all resolution.
			continue
		}
		query := append([]byte(nil), buf[:n]...)
		if resp := s.Answer(query); resp != nil {
			_, _ = pc.WriteTo(resp, from)
		}
	}
}

// Close stops the server early. ListenAndServe's ctx does the same.
func (s *Server) Close() error {
	s.mu.Lock()
	pc := s.pc
	s.mu.Unlock()
	if pc == nil {
		return nil
	}
	return pc.Close()
}

// Answer builds the response to one query, or nil when the packet is not
// something we can answer (malformed, or not a question at all). Exported for
// tests: the wire format is the part worth pinning down.
func (s *Server) Answer(query []byte) []byte {
	q, err := parseQuery(query)
	if err != nil {
		return nil
	}
	zone := strings.ToLower(strings.Trim(s.Zone, "."))
	name := strings.ToLower(strings.TrimSuffix(q.name, "."))

	// Names outside the zone get REFUSED, not NXDOMAIN: we are not
	// authoritative for them and saying "no such name" would be a lie the
	// resolver might cache.
	label, ok := strings.CutSuffix(name, "."+zone)
	if !ok {
		return buildResponse(q, rcodeRefused, nil)
	}
	if strings.Contains(label, ".") {
		// Only one label deep: node.dotlink, not a.b.dotlink.
		return buildResponse(q, rcodeNXDomain, nil)
	}

	rec, found := s.records()[label]
	if !found {
		// NXDOMAIN, not an empty answer: a revoked Node must fail fast
		// instead of making every tool wait for a connection timeout.
		return buildResponse(q, rcodeNXDomain, nil)
	}

	var answers []rr
	switch q.qtype {
	case typeA:
		if rec.IPv4.IsValid() && rec.IPv4.Is4() {
			answers = append(answers, rr{typ: typeA, ip: rec.IPv4})
		}
	case typeAAAA:
		if rec.IPv6.IsValid() {
			answers = append(answers, rr{typ: typeAAAA, ip: rec.IPv6})
		}
	case typeANY, typeCNAME, 0:
		// Some tools ask ANY. Answering with what we have is friendlier than
		// an empty NOERROR.
		if rec.IPv4.IsValid() && rec.IPv4.Is4() {
			answers = append(answers, rr{typ: typeA, ip: rec.IPv4})
		}
		if rec.IPv6.IsValid() {
			answers = append(answers, rr{typ: typeAAAA, ip: rec.IPv6})
		}
	default:
		// A valid name with no record of that type is NOERROR/NODATA, not
		// NXDOMAIN: the name exists, the type does not.
		return buildResponse(q, rcodeNoError, nil)
	}
	return buildResponse(q, rcodeNoError, answers)
}

func (s *Server) records() map[string]Record {
	if s.Lookup == nil {
		return nil
	}
	return s.Lookup()
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Wire format. Only what a resolver needs: no compression on input (a
// resolver's question never uses it), no EDNS, no DNSSEC.

const (
	typeA     uint16 = 1
	typeCNAME uint16 = 5
	typeAAAA  uint16 = 28
	typeANY   uint16 = 255

	classIN uint16 = 1

	rcodeNoError  uint8 = 0
	rcodeNXDomain uint8 = 3
	rcodeRefused  uint8 = 5

	flagResponse           = 0x8000
	flagAuthoritative      = 0x0400
	flagRecursionAvailable = 0x0080
)

type question struct {
	id    uint16
	name  string
	qtype uint16
}

type rr struct {
	typ uint16
	ip  netip.Addr
}

func parseQuery(b []byte) (question, error) {
	if len(b) < 12 {
		return question{}, errors.New("short header")
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	if flags&flagResponse != 0 {
		return question{}, errors.New("not a query")
	}
	if qd := binary.BigEndian.Uint16(b[4:6]); qd != 1 {
		return question{}, fmt.Errorf("question count %d", qd)
	}
	q := question{id: binary.BigEndian.Uint16(b[0:2])}
	name, off, err := readName(b, 12)
	if err != nil {
		return question{}, err
	}
	if off+4 > len(b) {
		return question{}, errors.New("truncated question")
	}
	q.name = name
	q.qtype = binary.BigEndian.Uint16(b[off : off+2])
	// Class must be IN; anything else (CHAOS, ANY) is not ours.
	if class := binary.BigEndian.Uint16(b[off+2 : off+4]); class != classIN && class != 255 {
		return question{}, fmt.Errorf("class %d", class)
	}
	return q, nil
}

func readName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	for {
		if off >= len(b) {
			return "", 0, errors.New("name runs past the packet")
		}
		n := int(b[off])
		off++
		if n == 0 {
			return sb.String(), off, nil
		}
		if n&0xc0 != 0 {
			// Compression pointers in a question are legal but no resolver
			// sends them; refusing beats looping on a malicious pointer.
			return "", 0, errors.New("compressed question name")
		}
		if off+n > len(b) {
			return "", 0, errors.New("label runs past the packet")
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(b[off : off+n])
		off += n
		if sb.Len() > 255 {
			return "", 0, errors.New("name too long")
		}
	}
}

func buildResponse(q question, rcode uint8, answers []rr) []byte {
	// Header: ID, flags, QD=1, AN, NS=0, AR=0.
	out := make([]byte, 12, 12+64)
	binary.BigEndian.PutUint16(out[0:2], q.id)
	flags := uint16(flagResponse|flagAuthoritative|flagRecursionAvailable)&0xfff0 | uint16(rcode)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], uint16(len(answers)))

	// The question is echoed back verbatim; a name pointer to offset 12 then
	// addresses it from every answer.
	for _, label := range strings.Split(strings.TrimSuffix(q.name, "."), ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	var qtype [4]byte
	binary.BigEndian.PutUint16(qtype[0:2], q.qtype)
	binary.BigEndian.PutUint16(qtype[2:4], classIN)
	out = append(out, qtype[:]...)

	for _, a := range answers {
		out = append(out, 0xc0, 0x0c)
		var fixed [10]byte
		binary.BigEndian.PutUint16(fixed[0:2], a.typ)
		binary.BigEndian.PutUint16(fixed[2:4], classIN)
		binary.BigEndian.PutUint32(fixed[4:8], 30) // TTL: short, so revocations land
		ip := a.ip.AsSlice()
		binary.BigEndian.PutUint16(fixed[8:10], uint16(len(ip)))
		out = append(out, fixed[:]...)
		out = append(out, ip...)
	}
	return out
}

// Label derives the DNS label a hostname gets. Both ends compute it the same
// way, so a Node's name does not depend on which side is talking.
func Label(hostname string) string {
	// "Mac-mini.local" and "mac mini" both mean mac-mini: the DNS name is
	// for typing, not for matching the system's hostname exactly.
	h := strings.ToLower(strings.TrimSpace(hostname))
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	var sb strings.Builder
	lastDash := false
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			sb.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_' || r == ' ':
			if !lastDash && sb.Len() > 0 {
				sb.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(sb.String(), "-")
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	if out == "" {
		return "node"
	}
	return out
}
