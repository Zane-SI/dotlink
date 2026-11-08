package control

import (
	"context"

	"github.com/Zane-SI/dotlink/internal/ctlapi"
	"github.com/Zane-SI/dotlink/internal/proto"
)

// Admin is the operator's handle on a running Control Plane. The `invite` CLI
// uses it; it speaks the same HTTP API as everything else, so there is no
// second code path that could drift from the server.
type Admin struct {
	ctlapi.Client
}

// NewAdmin returns a handle authorized by the admin token.
func NewAdmin(baseURL, adminToken string) *Admin {
	return &Admin{Client: ctlapi.Client{BaseURL: baseURL, Token: adminToken}}
}

// CreateInvite mints a one-shot Invite.
func (a *Admin) CreateInvite(ctx context.Context) (proto.Invite, error) {
	var inv proto.Invite
	err := a.Do(ctx, "POST", "/v1/admin/invites", nil, &inv)
	return inv, err
}

// ListInvites returns every Invite, used and unused.
func (a *Admin) ListInvites(ctx context.Context) ([]proto.Invite, error) {
	var out struct {
		Invites []proto.Invite `json:"invites"`
	}
	err := a.Do(ctx, "GET", "/v1/admin/invites", nil, &out)
	return out.Invites, err
}

// DeleteInvite revokes an unused Invite. A redeemed one is history and stays.
func (a *Admin) DeleteInvite(ctx context.Context, id string) error {
	return a.Do(ctx, "DELETE", "/v1/admin/invites/"+ctlapi.PathEscape(id), nil, nil)
}
