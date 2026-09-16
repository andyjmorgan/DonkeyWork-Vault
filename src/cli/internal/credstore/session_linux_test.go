package credstore

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestRepairSessionBus(t *testing.T) {
	present := filepath.Join(t.TempDir(), "present")
	if err := os.WriteFile(present, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"", "unix:abstract=test", "unix:path=%zz", "unix:path=/missing;unix:path=/other", "unix:path=" + present} {
		t.Run(address, func(t *testing.T) {
			t.Setenv("DBUS_SESSION_BUS_ADDRESS", address)
			repairSessionBus()
			if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != address {
				t.Fatal("changed a non-stale address")
			}
		})
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(t.TempDir(), "missing")+",guid=old")
	want := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	bus := filepath.Join("/run/user", strconv.Itoa(os.Getuid()), "bus")
	if fi, err := os.Stat(bus); err == nil && fi.Mode()&os.ModeSocket != 0 {
		want = "unix:path=" + bus
	}
	repairSessionBus()
	if got := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
