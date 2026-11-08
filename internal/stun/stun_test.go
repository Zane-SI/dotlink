package stun

import (
	"net/netip"
	"testing"
)

func TestReplyReportsTheSourceAddress(t *testing.T) {
	req := Request()
	if !IsBindingRequest(req) {
		t.Fatal("Request did not produce a binding request")
	}
	want := netip.MustParseAddrPort("203.0.113.7:51820")
	resp := Reply(req, want)
	if !IsBindingSuccess(resp) {
		t.Fatal("Reply did not produce a binding success")
	}
	got, err := ParseResponse(resp, req)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != want {
		t.Fatalf("mapped = %s, want %s", got, want)
	}
}

func TestResponseForAnotherTransactionIsRejected(t *testing.T) {
	req, other := Request(), Request()
	resp := Reply(other, netip.MustParseAddrPort("203.0.113.7:1"))
	if _, err := ParseResponse(resp, req); err == nil {
		t.Fatal("a response to another transaction was accepted")
	}
}

func TestGarbageIsNotSTUN(t *testing.T) {
	for _, frame := range [][]byte{
		nil,
		[]byte("DLK1"),
		[]byte("DLKRxxxxxxxxxxxxxxxxxxxxxx"),
		make([]byte, 19),
	} {
		if IsBindingRequest(frame) || IsBindingSuccess(frame) {
			t.Fatalf("%q was taken for STUN", frame)
		}
	}
	if _, err := ParseResponse([]byte("nope"), Request()); err == nil {
		t.Fatal("garbage parsed as a response")
	}
}

func TestReplyIgnoresNonRequests(t *testing.T) {
	if Reply([]byte("hello"), netip.MustParseAddrPort("1.2.3.4:5")) != nil {
		t.Fatal("replied to something that is not a request")
	}
}
