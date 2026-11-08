package punch

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Magic is the four bytes that tell the data path "this is a probe, not a
// WireGuard packet". Everything WireGuard sends starts with its own header,
// and the first four bytes of a WireGuard message are a fixed little-endian
// type (1..4), so there is no room for confusion.
var Magic = [4]byte{'D', 'L', 'K', '1'}

// Kind is the probe type. The value is also inside the sealed payload, so a
// flipped byte in the clear header turns into a decryption failure rather than
// a wrong action.
type Kind byte

const (
	KindPing Kind = 1
	KindPong Kind = 2
)

// Probe is what a decoded frame says. Sender is authenticated: the frame only
// opens with the private key that matches Sender, so a forged frame fails
// before it gets here.
type Probe struct {
	Kind   Kind
	Sender [32]byte
	SentAt time.Time
}

const (
	version     = 1
	headerLen   = 4 + 1 + 32 + 24 // magic, kind, sender, nonce
	plainLen    = 1 + 1 + 8       // version, kind, unix nanos
	overheadLen = headerLen + box.Overhead
)

// Ping builds a probe addressed to recipient but readable by anyone: the
// payload is sealed to recipient alone, so only that Node can answer, and only
// a Pong that opens proves the sender holds the matching private key.
func Ping(priv, sender, recipient [32]byte, now time.Time) []byte {
	return seal(KindPing, priv, sender, recipient, now)
}

// Pong answers a Ping. SentAt echoes the ping's timestamp so both sides can log
// the same round trip; the sender measures RTT against its own clock anyway,
// because two machines rarely agree on the time.
func Pong(priv, sender, recipient [32]byte, sentAt time.Time) []byte {
	return seal(KindPong, priv, sender, recipient, sentAt)
}

func seal(k Kind, priv, sender, recipient [32]byte, now time.Time) []byte {
	frame := make([]byte, headerLen, overheadLen)
	copy(frame[0:4], Magic[:])
	frame[4] = byte(k)
	copy(frame[5:37], sender[:])
	nonce := frame[37:61]
	if _, err := rand.Read(nonce); err != nil {
		// crypto/rand does not fail in practice; a probe is worthless if it
		// cannot be randomised, so refuse to make one.
		return nil
	}

	var plain [plainLen]byte
	plain[0] = version
	plain[1] = byte(k)
	binary.BigEndian.PutUint64(plain[2:], uint64(now.UnixNano()))

	var n [24]byte
	copy(n[:], nonce)
	recipientPub := recipient
	privCopy := priv
	return box.Seal(frame, plain[:], &n, &recipientPub, &privCopy)
}

// ErrNotAProbe reports a datagram that is not ours to decode.
var ErrNotAProbe = errors.New("punch: not a probe")

// ErrForged reports a frame that did not open: wrong key, wrong recipient, or
// tampering. Never act on one.
var ErrForged = errors.New("punch: frame did not authenticate")

// ErrStale reports a frame older than the accepted window. A replayed Ping
// should not move a peer onto a path.
var ErrStale = errors.New("punch: frame is outside the time window")

// Open decodes a frame addressed to us. localPriv is our private key;
// localPub is what peers address us by.
func Open(frame []byte, localPriv, localPub [32]byte, now time.Time, skew time.Duration) (Probe, error) {
	if len(frame) < overheadLen {
		return Probe{}, ErrNotAProbe
	}
	for i := range Magic {
		if frame[i] != Magic[i] {
			return Probe{}, ErrNotAProbe
		}
	}
	if Kind(frame[4]) != KindPing && Kind(frame[4]) != KindPong {
		return Probe{}, fmt.Errorf("%w: unknown kind %d", ErrNotAProbe, frame[4])
	}
	var sender [32]byte
	copy(sender[:], frame[5:37])
	var n [24]byte
	copy(n[:], frame[37:61])

	plain, ok := box.Open(nil, frame[61:], &n, &sender, &localPriv)
	if !ok || len(plain) != plainLen {
		return Probe{}, ErrForged
	}
	if plain[0] != version {
		return Probe{}, fmt.Errorf("%w: version %d", ErrForged, plain[0])
	}
	if Kind(plain[1]) != Kind(frame[4]) {
		return Probe{}, ErrForged
	}
	at := time.Unix(0, int64(binary.BigEndian.Uint64(plain[2:])))
	if skew > 0 {
		if d := now.Sub(at); d > skew || d < -skew {
			return Probe{}, ErrStale
		}
	}
	return Probe{Kind: Kind(plain[1]), Sender: sender, SentAt: at}, nil
}

// IsProbe reports whether the datagram starts with our magic. It is the
// multiplexing check the data path runs on every inbound packet.
func IsProbe(frame []byte) bool {
	return len(frame) >= len(Magic) && frame[0] == Magic[0] && frame[1] == Magic[1] &&
		frame[2] == Magic[2] && frame[3] == Magic[3]
}
