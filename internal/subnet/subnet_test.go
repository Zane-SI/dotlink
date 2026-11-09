package subnet

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseCanonicalizesAndSorts(t *testing.T) {
	got, err := Parse([]string{"192.168.1.9/24", "10.1.2.3/8", "192.168.1.0/24"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := "10.0.0.0/8,192.168.1.0/24"
	if strings.Join(got, ",") != want {
		t.Fatalf("Parse = %v, want %s", got, want)
	}
}

func TestParseRejectsBadAdvertisements(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"not a prefix", []string{"192.168.1.1"}, "is not a CIDR prefix"},
		{"default route", []string{"0.0.0.0/0"}, "exit nodes are not in v1"},
		{"v4 too broad", []string{"0.0.0.0/1"}, "too broad"},
		{"v6 too broad", []string{"::/1"}, "too broad"},
		{"v4 overlay", []string{"100.64.0.0/16"}, "overlaps the Overlay range"},
		{"v6 overlay", []string{"fd00::/48"}, "overlaps the Overlay range"},
		{"unspecified", []string{"0.0.0.0/8"}, "unspecified"},
		{"loopback", []string{"127.0.0.0/8"}, "loopback"},
		{"link-local", []string{"fe80::/64"}, "link-local"},
		{"multicast", []string{"239.0.0.0/8"}, "multicast"},
		{"v4 in v6", []string{"::ffff:192.168.1.0/120"}, "IPv4-mapped"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.in)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestNormalizeLimitIsShared(t *testing.T) {
	in := make([]netip.Prefix, 0, MaxRoutes+1)
	for i := 0; i <= MaxRoutes; i++ {
		in = append(in, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16))
	}
	if _, err := Normalize(in); err == nil || !strings.Contains(err.Error(), "at most 16") {
		t.Fatalf("Normalize error = %v, want the shared limit", err)
	}
}
