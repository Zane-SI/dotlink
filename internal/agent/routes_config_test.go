package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAdvertiseRoutesFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "advertise-routes")
	if err := os.WriteFile(path, []byte("# Gateway LANs\n192.168.1.0/24, 10.0.0.0/8\nfd00:1::/64\n"), 0o600); err != nil {
		t.Fatalf("write routes: %v", err)
	}
	t.Setenv("DOTLINK_ADVERTISE_ROUTES_FILE", path)

	routes, err := LoadAdvertiseRoutes()
	if err != nil {
		t.Fatalf("LoadAdvertiseRoutes: %v", err)
	}
	got := make([]string, 0, len(routes))
	for _, pr := range routes {
		got = append(got, pr.String())
	}
	want := "10.0.0.0/8,192.168.1.0/24,fd00:1::/64"
	if strings.Join(got, ",") != want {
		t.Fatalf("routes = %v, want %s", got, want)
	}
}

func TestLoadAdvertiseRoutesMissingFileMeansNotAGateway(t *testing.T) {
	t.Setenv("DOTLINK_ADVERTISE_ROUTES_FILE", filepath.Join(t.TempDir(), "missing"))
	routes, err := LoadAdvertiseRoutes()
	if err != nil || routes != nil {
		t.Fatalf("LoadAdvertiseRoutes = %v, %v; want nil, nil", routes, err)
	}
}

func TestLoadAdvertiseRoutesRejectsInvalidPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "advertise-routes")
	if err := os.WriteFile(path, []byte("not-a-prefix\n"), 0o600); err != nil {
		t.Fatalf("write routes: %v", err)
	}
	t.Setenv("DOTLINK_ADVERTISE_ROUTES_FILE", path)
	if _, err := LoadAdvertiseRoutes(); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v, want one naming %s", err, path)
	}
}
