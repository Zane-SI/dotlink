package agent

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/Zane-SI/dotlink/internal/subnet"
)

// defaultAdvertiseRoutesPath is where the launch daemon looks for its LAN
// prefixes. A flag on the command line wins; this file exists so the launchd
// job can be a Gateway without editing the plist by hand.
const defaultAdvertiseRoutesPath = "/usr/local/etc/dotlink/advertise-routes"

// AdvertiseRoutesPath returns the configured routes file. Tests point
// DOTLINK_ADVERTISE_ROUTES_FILE at a temporary file.
func AdvertiseRoutesPath() string {
	if p := os.Getenv("DOTLINK_ADVERTISE_ROUTES_FILE"); p != "" {
		return p
	}
	return defaultAdvertiseRoutesPath
}

// LoadAdvertiseRoutes reads LAN prefixes from AdvertiseRoutesPath. A missing
// file means this Node is not a Gateway. The format is the same comma or
// newline separated list as --advertise-routes; # starts a comment.
func LoadAdvertiseRoutes() ([]netip.Prefix, error) {
	path := AdvertiseRoutesPath()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var fields []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields = append(fields, strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\r'
		})...)
	}
	cleaned, err := subnet.Parse(fields)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	routes := make([]netip.Prefix, 0, len(cleaned))
	for _, raw := range cleaned {
		pr, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		routes = append(routes, pr)
	}
	return routes, nil
}
