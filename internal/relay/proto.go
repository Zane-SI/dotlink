// Package relay implements Dotlink's own UDP Relay: the smallest forwarding
// hop that can carry WireGuard between two Nodes that cannot reach each other
// directly.
//
// The Relay never sees plaintext. A frame is [4-byte magic][kind][body], and
// the only thing the Relay does with a KindData frame is look up the 32-byte
// destination key in its table and rewrite the UDP destination address. It
// holds a registration table of key → address, established by a signed HELLO,
// and nothing else: no peer state, no flow state, no content.
package relay

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"
)

const (
	// Magic marks every frame a Dotlink Agent or Relay produces. It is
	// deliberately one byte away from WireGuard's own framing so that a
	// misrouted WireGuard packet can never be mistaken for a Relay frame.
	Magic = "DLKR"

	// Version of the frame layout. Bumped when the body layout changes.
	Version byte = 1

	headerLen  = len(Magic) + 1
	helloLen   = headerLen + 1 + 8 + 32 + 32
	helloOKLen = headerLen + 8
	dataLen    = headerLen + 32
)

// Kind is the second field of every frame.
type Kind byte

const (
	KindHello   Kind = 1 // Agent → Relay: register this key at this address
	KindHelloOK Kind = 2 // Relay → Agent: you are registered
	KindData    Kind = 3 // both ways: [key] + opaque payload
	KindError   Kind = 4 // Relay → Agent: this frame was rejected
)

// Error codes carried by a KindError frame. They exist so that a misconfigured
// Agent fails loudly instead of timing out silently.
const (
	ErrCodeBadFrame    byte = 1
	ErrCodeUnknownPeer byte = 2
)

var (
	ErrBadMagic       = errors.New("relay: not a Dotlink frame")
	ErrBadVersion     = errors.New("relay: unsupported frame version")
	ErrShortFrame     = errors.New("relay: truncated frame")
	ErrWrongKind      = errors.New("relay: unexpected frame kind")
	ErrBadSignature   = errors.New("relay: bad hello signature")
	ErrStaleTimestamp = errors.New("relay: hello timestamp outside the allowed window")
)

// Hello builds a registration frame. The HMAC covers the version, the
// timestamp and the key, so neither the identity nor the clock can be edited
// by anyone who does not hold the Relay secret.
func Hello(buf []byte, pub [32]byte, ts time.Time, secret []byte) []byte {
	buf = append(buf[:0], Magic...)
	buf = append(buf, byte(KindHello), Version)
	buf = binary.BigEndian.AppendUint64(buf, uint64(ts.Unix()))
	buf = append(buf, pub[:]...)
	return append(buf, helloMAC(secret, Version, ts.Unix(), pub)...)
}

func helloMAC(secret []byte, version byte, unix int64, pub [32]byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte{version})
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(unix))
	m.Write(ts[:])
	m.Write(pub[:])
	return m.Sum(nil)
}

// ParseHello validates a registration frame and returns the key it claims.
// skew is the tolerance in either direction: a replayed frame older than that
// is refused, which is what stops an observer from re-registering a captured
// HELLO under its own address later.
func ParseHello(f []byte, secret []byte, now time.Time, skew time.Duration) (pub [32]byte, ts time.Time, err error) {
	if len(f) < helloLen {
		if len(f) >= headerLen && string(f[:len(Magic)]) == Magic {
			return pub, ts, ErrShortFrame
		}
		return pub, ts, ErrBadMagic
	}
	if string(f[:len(Magic)]) != Magic {
		return pub, ts, ErrBadMagic
	}
	if f[len(Magic)] != byte(KindHello) {
		return pub, ts, ErrWrongKind
	}
	body := f[headerLen:]
	if body[0] != Version {
		return pub, ts, ErrBadVersion
	}
	unix := int64(binary.BigEndian.Uint64(body[1:9]))
	copy(pub[:], body[9:41])
	want := helloMAC(secret, body[0], unix, pub)
	if subtle.ConstantTimeCompare(want, body[41:73]) != 1 {
		return pub, ts, ErrBadSignature
	}
	ts = time.Unix(unix, 0).UTC()
	if d := now.Sub(ts); d > skew || d < -skew {
		return pub, ts, ErrStaleTimestamp
	}
	return pub, ts, nil
}

// HelloOK acknowledges a registration. The Agent treats it as "the Relay has
// me in its table right now", which is also how it notices that the Relay was
// restarted: the table was forgotten, so the next HELLO has to be answered
// again.
func HelloOK(buf []byte, ts time.Time) []byte {
	buf = append(buf[:0], Magic...)
	buf = append(buf, byte(KindHelloOK))
	return binary.BigEndian.AppendUint64(buf, uint64(ts.Unix()))
}

func ParseHelloOK(f []byte) (ts time.Time, err error) {
	if len(f) < helloOKLen {
		return ts, ErrShortFrame
	}
	if string(f[:len(Magic)]) != Magic {
		return ts, ErrBadMagic
	}
	if f[len(Magic)] != byte(KindHelloOK) {
		return ts, ErrWrongKind
	}
	return time.Unix(int64(binary.BigEndian.Uint64(f[headerLen:helloOKLen])), 0).UTC(), nil
}

// Data wraps an opaque payload for delivery to key. Neither direction of the
// Relay link interprets the payload.
func Data(buf []byte, key [32]byte, payload []byte) []byte {
	buf = append(buf[:0], Magic...)
	buf = append(buf, byte(KindData))
	buf = append(buf, key[:]...)
	return append(buf, payload...)
}

// ParseData returns the key the frame is addressed to (or came from, on the
// Agent side) and the payload, which aliases f.
func ParseData(f []byte) (key [32]byte, payload []byte, err error) {
	switch {
	case len(f) < dataLen:
		if len(f) >= headerLen && string(f[:len(Magic)]) == Magic {
			return key, nil, ErrShortFrame
		}
		return key, nil, ErrBadMagic
	case string(f[:len(Magic)]) != Magic:
		return key, nil, ErrBadMagic
	case f[len(Magic)] != byte(KindData):
		return key, nil, ErrWrongKind
	}
	copy(key[:], f[headerLen:dataLen])
	return key, f[dataLen:], nil
}

func Error(buf []byte, code byte, msg string) []byte {
	buf = append(buf[:0], Magic...)
	buf = append(buf, byte(KindError), code)
	return append(buf, msg...)
}

func ParseError(f []byte) (code byte, msg string, err error) {
	if len(f) < headerLen+1 {
		return 0, "", ErrShortFrame
	}
	if string(f[:len(Magic)]) != Magic {
		return 0, "", ErrBadMagic
	}
	if f[len(Magic)] != byte(KindError) {
		return 0, "", ErrWrongKind
	}
	return f[headerLen], string(f[headerLen+1:]), nil
}

// KindOf reports the kind of a Dotlink frame. ok is false for anything that
// is not one, which is how a raw WireGuard packet is told apart.
func KindOf(f []byte) (k Kind, ok bool) {
	if len(f) < headerLen || string(f[:len(Magic)]) != Magic {
		return 0, false
	}
	return Kind(f[len(Magic)]), true
}
