// Package stun implements the one thing Dotlink needs from RFC 5389: ask a
// server what address it saw us coming from, and answer that question.
//
// A full STUN implementation is unnecessary here. The Relay already listens on
// a UDP port that every Agent can reach, so it doubles as the STUN server and
// the answer comes back over the same socket the punch will use — which means
// the mapping it reports is the mapping that matters.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	magicCookie = 0x2112A442
	headerLen   = 20
	// bindingRequest and bindingSuccess are the only two message types we
	// speak. Everything else is dropped, including the legacy RFC 3489 types.
	bindingRequest = 0x0001
	bindingSuccess = 0x0101
	attrMapped     = 0x0001
	attrXorMapped  = 0x0020
)

// ErrNotSTUN reports a datagram that is not a STUN message at all.
var ErrNotSTUN = errors.New("stun: not a STUN message")

// IsBindingRequest reports whether frame is a STUN binding request. The check
// is the first thing the data path runs on an inbound datagram, so it must be
// cheap and must never accept a WireGuard or Dotlink packet by accident.
func IsBindingRequest(frame []byte) bool {
	return len(frame) >= headerLen &&
		frame[0] == 0x00 && frame[1] == 0x01 &&
		binary.BigEndian.Uint32(frame[4:8]) == magicCookie
}

// IsBindingSuccess reports whether frame answers a binding request.
func IsBindingSuccess(frame []byte) bool {
	return len(frame) >= headerLen &&
		frame[0] == 0x01 && frame[1] == 0x01 &&
		binary.BigEndian.Uint32(frame[4:8]) == magicCookie
}

// Request builds a binding request. The transaction ID is random; it is what
// ties a response to this request.
func Request() []byte {
	msg := make([]byte, headerLen)
	binary.BigEndian.PutUint16(msg[0:2], bindingRequest)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	if _, err := rand.Read(msg[8:20]); err != nil {
		return nil
	}
	return msg
}

// Reply builds the binding success answer to request, reporting addr as the
// source's public mapping.
func Reply(request []byte, addr netip.AddrPort) []byte {
	if !IsBindingRequest(request) {
		return nil
	}
	attr := xorMapped(addr, request[8:20])
	msg := make([]byte, headerLen+4, headerLen+4+len(attr))
	copy(msg, request[:headerLen])
	binary.BigEndian.PutUint16(msg[0:2], bindingSuccess)
	binary.BigEndian.PutUint16(msg[2:4], uint16(4+len(attr)))
	binary.BigEndian.PutUint16(msg[headerLen:], attrXorMapped)
	binary.BigEndian.PutUint16(msg[headerLen+2:], uint16(len(attr)))
	return append(msg, attr...)
}

// ParseResponse reads the mapped address out of a binding success reply that
// answers the given request.
func ParseResponse(resp, request []byte) (netip.AddrPort, error) {
	if len(resp) < headerLen || !IsBindingRequest(request) {
		return netip.AddrPort{}, ErrNotSTUN
	}
	if binary.BigEndian.Uint16(resp[0:2]) != bindingSuccess {
		return netip.AddrPort{}, ErrNotSTUN
	}
	if binary.BigEndian.Uint32(resp[4:8]) != magicCookie {
		return netip.AddrPort{}, ErrNotSTUN
	}
	// The transaction ID must match: an off-path attacker cannot inject a
	// mapping without it.
	if string(resp[8:20]) != string(request[8:20]) {
		return netip.AddrPort{}, errors.New("stun: response is for another transaction")
	}
	for off := headerLen; off+4 <= len(resp); {
		typ := binary.BigEndian.Uint16(resp[off:])
		length := int(binary.BigEndian.Uint16(resp[off+2:]))
		val := resp[off+4:]
		if length > len(val) {
			break
		}
		switch typ {
		case attrXorMapped:
			return parseXor(val[:length], request[8:20])
		case attrMapped:
			return parsePlain(val[:length])
		}
		off += 4 + (length+3)&^3 // attributes are padded to four bytes
	}
	return netip.AddrPort{}, errors.New("stun: no mapped address in the response")
}

func xorMapped(addr netip.AddrPort, txID []byte) []byte {
	ip := addr.Addr().As4()
	out := make([]byte, 8)
	out[1] = 0x01 // family: IPv4
	binary.BigEndian.PutUint16(out[2:], addr.Port()^uint16(magicCookie>>16))
	for i := 0; i < 4; i++ {
		out[4+i] = ip[i] ^ txID[i]
	}
	return out
}

func parseXor(val []byte, txID []byte) (netip.AddrPort, error) {
	if len(val) < 8 || val[1] != 0x01 {
		return netip.AddrPort{}, errors.New("stun: unsupported address family")
	}
	var ip [4]byte
	for i := 0; i < 4; i++ {
		ip[i] = val[4+i] ^ txID[i]
	}
	port := binary.BigEndian.Uint16(val[2:]) ^ uint16(magicCookie>>16)
	return netip.AddrPortFrom(netip.AddrFrom4(ip), port), nil
}

func parsePlain(val []byte) (netip.AddrPort, error) {
	if len(val) < 8 || val[1] != 0x01 {
		return netip.AddrPort{}, errors.New("stun: unsupported address family")
	}
	var ip [4]byte
	copy(ip[:], val[4:8])
	return netip.AddrPortFrom(netip.AddrFrom4(ip), binary.BigEndian.Uint16(val[2:])), nil
}
