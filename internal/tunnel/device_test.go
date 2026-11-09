package tunnel

import (
	"net/netip"
	"strings"
	"testing"
)

func key(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestPeerOpsAddsANewPeerInFull(t *testing.T) {
	ops, next := peerOps(nil, []Peer{{
		Pub:      key(1),
		Prefixes: []netip.Prefix{prefix("100.64.0.2/32")},
	}})
	for _, want := range []string{
		"public_key=0101010101010101010101010101010101010101010101010101010101010101\n",
		"endpoint=pk:0101010101010101010101010101010101010101010101010101010101010101\n",
		"allowed_ip=100.64.0.2/32\n",
	} {
		if !strings.Contains(ops, want) {
			t.Errorf("ops missing %q:\n%s", want, ops)
		}
	}
	if strings.Contains(ops, "remove") {
		t.Errorf("adding a peer must not remove anything:\n%s", ops)
	}
	if len(next) != 1 {
		t.Errorf("tracked %d peers, want 1", len(next))
	}
}

func TestPeerOpsRemovesOnlyTheMissingPeer(t *testing.T) {
	prev := map[[32]byte][]netip.Prefix{
		key(1): {prefix("100.64.0.2/32")},
		key(2): {prefix("100.64.0.3/32")},
	}
	ops, next := peerOps(prev, []Peer{{Pub: key(2), Prefixes: []netip.Prefix{prefix("100.64.0.3/32")}}})

	if !strings.Contains(ops, "public_key=0101010101010101010101010101010101010101010101010101010101010101\nremove=true\n") {
		t.Errorf("missing removal of the peer that left:\n%s", ops)
	}
	if strings.Contains(ops, "public_key=0202") {
		t.Errorf("touched the peer that did not change:\n%s", ops)
	}
	if len(next) != 1 {
		t.Errorf("tracked %d peers, want 1", len(next))
	}
}

func TestPeerOpsRewritesAllowedIPsWithoutDroppingTheSession(t *testing.T) {
	prev := map[[32]byte][]netip.Prefix{key(1): {prefix("100.64.0.2/32")}}
	ops, _ := peerOps(prev, []Peer{{
		Pub:      key(1),
		Prefixes: []netip.Prefix{prefix("100.64.0.2/32"), prefix("192.168.1.0/24")},
	}})

	if !strings.Contains(ops, "replace_allowed_ips=true") {
		t.Errorf("stale prefixes would survive:\n%s", ops)
	}
	if strings.Contains(ops, "endpoint=") || strings.Contains(ops, "remove=true") {
		t.Errorf("a prefix change must not reset the endpoint or drop the peer:\n%s", ops)
	}
	if !strings.Contains(ops, "allowed_ip=192.168.1.0/24") {
		t.Errorf("the new Subnet Route is missing:\n%s", ops)
	}
}

func TestPeerOpsIsSilentWhenNothingChanged(t *testing.T) {
	peers := []Peer{{Pub: key(1), Prefixes: []netip.Prefix{prefix("100.64.0.2/32")}}}
	prev := map[[32]byte][]netip.Prefix{key(1): peers[0].Prefixes}
	if ops, _ := peerOps(prev, peers); ops != "" {
		t.Fatalf("re-sent a config that did not change:\n%s", ops)
	}
}

func TestPeerOpsIsDeterministic(t *testing.T) {
	prev := map[[32]byte][]netip.Prefix{key(3): nil, key(1): nil, key(2): nil}
	first, _ := peerOps(prev, nil)
	for i := 0; i < 20; i++ {
		again, _ := peerOps(prev, nil)
		if again != first {
			t.Fatalf("removal order is not stable:\n%s\nvs\n%s", first, again)
		}
	}
}
