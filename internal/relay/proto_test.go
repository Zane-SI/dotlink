package relay

import (
	"bytes"
	"testing"
	"time"
)

func key(seed byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = seed
	}
	return k
}

var now = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func TestHelloRoundTrip(t *testing.T) {
	secret, pub := []byte("relay-secret"), key(0xa1)

	f := Hello(nil, pub, now, secret)
	got, ts, err := ParseHello(f, secret, now, time.Minute)
	if err != nil {
		t.Fatalf("ParseHello: %v", err)
	}
	if got != pub {
		t.Fatalf("pubkey = %x, want %x", got, pub)
	}
	if !ts.Equal(now.Truncate(time.Second)) && !ts.Equal(now) {
		t.Fatalf("timestamp = %v, want %v", ts, now)
	}
}

func TestParseHelloRejectsWhatItShould(t *testing.T) {
	secret, pub := []byte("relay-secret"), key(0xa1)
	good := Hello(nil, pub, now, secret)

	tampered := bytes.Clone(good)
	tampered[len(tampered)-1] ^= 0xff

	wrongKey := bytes.Clone(good)
	wrongKey[20] ^= 0xff

	cases := []struct {
		name string
		f    []byte
		now  time.Time
	}{
		{"not a relay frame", []byte("GET / HTTP/1.1\r\n"), now},
		{"truncated", good[:len(good)-1], now},
		{"tampered", tampered, now},
		{"tampered pubkey", wrongKey, now},
		{"stale", good, now.Add(61 * time.Second)},
		{"from the future", good, now.Add(-61 * time.Second)},
	}
	for _, c := range cases {
		if _, _, err := ParseHello(c.f, secret, c.now, time.Minute); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestParseHelloRejectsWrongSecret(t *testing.T) {
	f := Hello(nil, key(1), now, []byte("relay-secret"))
	if _, _, err := ParseHello(f, []byte("other-secret"), now, time.Minute); err != ErrBadSignature {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestDataRoundTrip(t *testing.T) {
	dst := key(0x42)
	payload := []byte("wireguard bytes that are not valid wireguard bytes")

	f := Data(nil, dst, payload)
	gotDst, gotPayload, err := ParseData(f)
	if err != nil {
		t.Fatalf("ParseData: %v", err)
	}
	if gotDst != dst {
		t.Fatalf("dst = %x, want %x", gotDst, dst)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload = %q, want %q", gotPayload, payload)
	}
}

func TestParseDataRejects(t *testing.T) {
	for _, f := range [][]byte{
		nil,
		[]byte("DLK1"),
		Hello(nil, key(1), now, []byte("s")),
		Data(nil, key(1), nil)[:len(Data(nil, key(1), nil))-1],
	} {
		if _, _, err := ParseData(f); err == nil {
			t.Errorf("accepted %q", f)
		}
	}
}

func TestHelloOKRoundTrip(t *testing.T) {
	f := HelloOK(nil, now)
	ts, err := ParseHelloOK(f)
	if err != nil {
		t.Fatalf("ParseHelloOK: %v", err)
	}
	if !ts.Equal(now) {
		t.Fatalf("ts = %v, want %v", ts, now)
	}
}

func TestKindOf(t *testing.T) {
	if k, ok := KindOf(Hello(nil, key(1), now, []byte("s"))); !ok || k != KindHello {
		t.Fatalf("hello kind = %v %v", k, ok)
	}
	if _, ok := KindOf([]byte("\x01\x00\x00\x00")); ok {
		t.Fatal("non-magic frame reported as relay frame")
	}
}
