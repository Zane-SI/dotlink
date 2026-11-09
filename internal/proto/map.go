package proto

import "time"

// Network is the single Network a Control Plane serves.
type Network struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

// Relay is the server an Agent falls back to when hole punching fails.
// It is infrastructure, not a Node: it forwards sealed packets and can read none.
type Relay struct {
	ID   string `json:"id"`
	UDP  string `json:"udp"`
	DERP string `json:"derp"`
	// Secret is the network-wide shared secret the Relay checks the HELLO
	// HMAC against. It rides in the map because every enrolled Node already
	// trusts the Control Plane, and making users paste a second credential
	// after scanning a QR code would be absurd.
	Secret string `json:"secret,omitempty"`
}

// Candidate is one address where a Node might be reachable.
// Kind is "stun" for a public mapping, "lan" for a local address.
type Candidate struct {
	Addr string `json:"addr"`
	Kind string `json:"kind"`
}

// Self is the asking Node's own view of itself in the Peer Map.
type Self struct {
	NodeID   string `json:"node_id"`
	Hostname string `json:"hostname"`
	// DNSName is the label the Node answers to under the Network's domain,
	// derived by the Control Plane so both ends agree without a round trip.
	DNSName string `json:"dns_name,omitempty"`
	IPv4    string `json:"ipv4"`
	IPv6    string `json:"ipv6"`
}

// Node is another Node in the same Network. The map's JSON key for these
// is "peers" (docs/spec/v1.md §3.2); everywhere else the term is Node.
type Node struct {
	NodeID   string `json:"node_id"`
	Hostname string `json:"hostname"`
	// DNSName is the label this Node answers to under the Network's domain:
	// "mac-mini" for mac-mini.dotlink. The Control Plane derives it and
	// refuses a second Node that would claim the same one.
	DNSName      string      `json:"dns_name,omitempty"`
	Pubkey       string      `json:"pubkey"`
	IPv4         string      `json:"ipv4"`
	IPv6         string      `json:"ipv6"`
	Candidates   []Candidate `json:"candidates"`
	SubnetRoutes []string    `json:"subnet_routes"`
	Online       bool        `json:"online"`
	LastSeen     time.Time   `json:"last_seen"`
}

// PeerMap is the whole Network as seen by one Node. v1 always sends the full
// map: a single Network of a few dozen Nodes is not worth a diff protocol.
type PeerMap struct {
	Version int64   `json:"version"`
	Self    Self    `json:"self"`
	Network Network `json:"network"`
	Peers   []Node  `json:"peers"`
	Relays  []Relay `json:"relays"`
}
