package credstore

import (
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// repairSessionBus recovers from a stale dbus-launch address inherited by a
// long-lived shell. Only replace a single Unix path address whose socket has
// disappeared, and only when the standard per-user bus exists.
func repairSessionBus() {
	address := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if !strings.HasPrefix(address, "unix:path=") || strings.Contains(address, ";") {
		return
	}
	path, _, _ := strings.Cut(strings.TrimPrefix(address, "unix:path="), ",")
	path, err := url.PathUnescape(path)
	if err != nil {
		return
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) { //nolint:gosec // G703: checking existence of the caller-selected D-Bus socket; no file contents are read
		return
	}
	bus := filepath.Join("/run/user", strconv.Itoa(os.Getuid()), "bus")
	if fi, err := os.Stat(bus); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+bus)
	}
}
