package proto

// EnrollRequest redeems an Invite. The Node generates its keypair locally and
// sends only the public half, so a leaked Invite cannot impersonate a Node.
type EnrollRequest struct {
	Invite     string      `json:"invite"`
	Pubkey     string      `json:"pubkey"`
	Hostname   string      `json:"hostname"`
	OS         string      `json:"os"`
	Candidates []Candidate `json:"candidates,omitempty"`
}

// EnrollResponse is everything a fresh Node needs to start.
type EnrollResponse struct {
	NodeID     string  `json:"node_id"`
	NodeToken  string  `json:"node_token"`
	IPv4       string  `json:"ipv4"`
	IPv6       string  `json:"ipv6"`
	Network    Network `json:"network"`
	Relays     []Relay `json:"relays"`
	MapVersion int64   `json:"map_version"`
}
