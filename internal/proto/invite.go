// Package proto holds the wire types shared by the Control Plane, the Agent
// and the Client. Field names are the JSON contract; see docs/spec/v1.md §3.2.
package proto

import "time"

// Invite is a one-shot, 24-hour credential that lets a new Node enroll.
// It carries no key material: the Node generates its own keypair and only
// hands the Control Plane the public half.
type Invite struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedBy    string    `json:"used_by,omitempty"`
}
