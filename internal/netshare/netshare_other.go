//go:build !darwin

package netshare

import (
	"context"
	"fmt"
	"runtime"

	"github.com/Zane-SI/dotlink/internal/netcfg"
)

// Enable is not implemented off macOS yet: Linux wants nftables and Windows
// wants WinNAT, and shipping one of them from a machine where it cannot be
// tested would be worse than an honest refusal.
func Enable(context.Context, netcfg.Runner, Config) (func(), error) {
	return nil, fmt.Errorf("Subnet Router is not implemented on %s yet", runtime.GOOS)
}
