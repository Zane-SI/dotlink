// Package derp speaks the subset of Tailscale's DERP protocol that Dotlink
// needs: a TLS stream between an Agent and a Relay, framed packets addressed
// by public key, keepalives and pings.
//
// It exists because UDP is not always available. A network that drops or
// throttles UDP still carries HTTPS, and the Relay is the one box both ends
// can reach. The framing follows upstream DERP so a stock `derper` can stand
// in for our server without touching the Agent.
package derp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ProtocolVersion is what we advertise in ClientInfo. Two is the version that
// added Ping/Pong and the health frame, which is the oldest one that still
// matches current clients.
const ProtocolVersion = 2

// frameType mirrors derp's wire types. The numbers matter: a stock derper and
// a stock client both key off them.
type frameType byte

const (
	frameServerKey     frameType = 0x01
	frameClientInfo    frameType = 0x02
	frameSendPacket    frameType = 0x03
	frameRecvPacket    frameType = 0x04
	frameKeepAlive     frameType = 0x05
	frameNotePreferred frameType = 0x06
	framePeerGone      frameType = 0x07
	framePeerPresent   frameType = 0x08
	framePing          frameType = 0x0c
	framePong          frameType = 0x0d
	frameHealth        frameType = 0x0e
	frameRestarting    frameType = 0x0f
)

const (
	keyLen = 32
	// maxFrame bounds what we will allocate for one frame. DERP carries
	// WireGuard packets, so a megabyte is already absurdly generous.
	maxFrame = 1 << 20
	// pingLen is the payload of a Ping/Pong: eight opaque bytes the peer
	// echoes back.
	pingLen = 8
)

// ErrClientClosed reports a closed client or a server that stopped serving.
var ErrClientClosed = errors.New("derp: client is closed")

// ErrUnknownPeer reports a SendPacket for a key that is not connected.
var ErrUnknownPeer = errors.New("derp: peer is not connected")

// readFrame reads one length-prefixed frame. The length covers the type byte
// plus the payload, which is what upstream DERP does.
func readFrame(r *bufio.Reader) (frameType, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 1 || n > maxFrame {
		return 0, nil, fmt.Errorf("derp: frame of %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return frameType(buf[0]), buf[1:], nil
}

// writeFrame writes one frame in a single Write call: two writers on one
// stream would interleave and corrupt each other.
func writeFrame(w io.Writer, typ frameType, payload []byte) error {
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], uint32(1+len(payload)))
	buf[4] = byte(typ)
	copy(buf[5:], payload)
	_, err := w.Write(buf)
	return err
}

func sendPacketBody(dst [32]byte, payload []byte) []byte {
	body := make([]byte, keyLen+len(payload))
	copy(body[:keyLen], dst[:])
	copy(body[keyLen:], payload)
	return body
}

func parseRecvPacket(body []byte) (src [32]byte, payload []byte, err error) {
	if len(body) < keyLen {
		return src, nil, errors.New("derp: short RecvPacket")
	}
	copy(src[:], body[:keyLen])
	return src, body[keyLen:], nil
}

// clientInfo is the ClientInfo frame: a version, the public key, and then
// whatever the client wants to say (we send nothing).
func clientInfoBody(pub [32]byte) []byte {
	body := make([]byte, 1+keyLen)
	body[0] = ProtocolVersion
	copy(body[1:], pub[:])
	return body
}

func parseClientInfo(body []byte) (pub [32]byte, err error) {
	if len(body) < 1+keyLen {
		return pub, errors.New("derp: short ClientInfo")
	}
	if body[0] != ProtocolVersion {
		return pub, fmt.Errorf("derp: protocol version %d", body[0])
	}
	copy(pub[:], body[1:1+keyLen])
	return pub, nil
}

// shortKey is the public key in the eight characters a log line can afford.
func shortKey(k [32]byte) string {
	return fmt.Sprintf("%x", k[:4])
}
