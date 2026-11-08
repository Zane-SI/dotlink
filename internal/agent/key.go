package agent

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
)

// PrivateKey decodes the Node's WireGuard private key. It is base64 in the
// state file because that is what the enrollment API speaks; WireGuard's UAPI
// wants hex, so the conversion happens at the tunnel boundary.
func (st State) PrivateKey() ([32]byte, error) {
	return decodeKey(st.PrivKey)
}

// PublicKey derives the public half, which is the Node's identity on the
// Relay and in every other Node's Peer Map.
func (st State) PublicKey() ([32]byte, error) {
	priv, err := st.PrivateKey()
	if err != nil {
		return [32]byte{}, err
	}
	key, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("load private key: %w", err)
	}
	var pub [32]byte
	copy(pub[:], key.PublicKey().Bytes())
	return pub, nil
}

func decodeKey(b64 string) ([32]byte, error) {
	var out [32]byte
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return out, fmt.Errorf("decode key: %w", err)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("decode key: got %d bytes, want 32", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
