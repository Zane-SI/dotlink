package proto

import "time"

// Network is the single Network a Control Plane serves.
type Network struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

// Relay is a node the Agent can fall back to when hole punching fails.
type Relay struct {
	ID   string `json:"id"`
	UDP  string `json:"udp"`
	DERP string `json:"derp"`
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
	IPv4     string `json:"ipv4"`
	IPv6     string `json:"ipv6"`
	Hostname string `json:"hostname"`
}

// Peer is another Node in the same Network.
type Peer struct {
	NodeID       string      `json:"node_id"`
	Hostname     string      `json:"hostname"`
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
	Peers   []Peer  `json:"peers"`
	Relays  []Relay `json:"relays"`
}
