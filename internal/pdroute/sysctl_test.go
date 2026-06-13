package pdroute

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeProc builds a scratch /proc/sys tree and points the package at it.
func fakeProc(t *testing.T, ifaces map[string]map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	old := sysctlBase
	sysctlBase = dir
	t.Cleanup(func() { sysctlBase = old })
	for ifc, keys := range ifaces {
		base := filepath.Join(dir, "net/ipv6/conf", ifc)
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}
		for k, v := range keys {
			if err := os.WriteFile(filepath.Join(base, k), []byte(v+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

func readVal(t *testing.T, iface, key string) string {
	t.Helper()
	v, err := readSysctl(sysctlPath(iface, key))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func newReg() *sysctlReg { return &sysctlReg{entries: map[string]*sysctlEntry{}} }

func TestSysctlAcceptRAOneBecomesTwoAndRestores(t *testing.T) {
	fakeProc(t, map[string]map[string]string{"wlan0": {"accept_ra": "1"}})
	s := newReg()
	s.acquireAcceptRA("wlan0")
	if got := readVal(t, "wlan0", "accept_ra"); got != "2" {
		t.Fatalf("accept_ra = %s, want 2", got)
	}
	s.releaseAcceptRA("wlan0")
	if got := readVal(t, "wlan0", "accept_ra"); got != "1" {
		t.Fatalf("accept_ra after release = %s, want 1", got)
	}
}

func TestSysctlAcceptRAZeroUntouched(t *testing.T) {
	fakeProc(t, map[string]map[string]string{"wlan0": {"accept_ra": "0"}})
	s := newReg()
	s.acquireAcceptRA("wlan0")
	if got := readVal(t, "wlan0", "accept_ra"); got != "0" {
		t.Fatalf("accept_ra = %s, want 0 (admin-disabled must be respected)", got)
	}
	s.releaseAcceptRA("wlan0")
	if got := readVal(t, "wlan0", "accept_ra"); got != "0" {
		t.Fatalf("accept_ra after release = %s, want 0", got)
	}
}

func TestSysctlForwardingRefcountSharedUplink(t *testing.T) {
	fakeProc(t, map[string]map[string]string{"wlan0": {"forwarding": "0"}})
	s := newReg()
	s.acquireForwarding("wlan0") // bridge 1
	s.acquireForwarding("wlan0") // bridge 2
	if got := readVal(t, "wlan0", "forwarding"); got != "1" {
		t.Fatalf("forwarding = %s, want 1", got)
	}
	s.releaseForwarding("wlan0")
	if got := readVal(t, "wlan0", "forwarding"); got != "1" {
		t.Fatalf("forwarding after first release = %s, want 1 (still referenced)", got)
	}
	s.releaseForwarding("wlan0")
	if got := readVal(t, "wlan0", "forwarding"); got != "0" {
		t.Fatalf("forwarding after last release = %s, want 0", got)
	}
}

func TestSysctlForwardingAlreadyOnUntouched(t *testing.T) {
	fakeProc(t, map[string]map[string]string{"wlan0": {"forwarding": "1"}})
	s := newReg()
	s.acquireForwarding("wlan0")
	s.releaseForwarding("wlan0")
	if got := readVal(t, "wlan0", "forwarding"); got != "1" {
		t.Fatalf("forwarding = %s, want 1 (was on before us; not ours to turn off)", got)
	}
}

func TestSysctlConcurrentChangeWins(t *testing.T) {
	fakeProc(t, map[string]map[string]string{"wlan0": {"accept_ra": "1"}})
	s := newReg()
	s.acquireAcceptRA("wlan0")
	// netd rewrites the value while we hold it
	if err := writeSysctl(sysctlPath("wlan0", "accept_ra"), "0"); err != nil {
		t.Fatal(err)
	}
	s.releaseAcceptRA("wlan0")
	if got := readVal(t, "wlan0", "accept_ra"); got != "0" {
		t.Fatalf("accept_ra = %s, want 0 (concurrent change must win)", got)
	}
}

func TestSysctlMissingPathHarmless(t *testing.T) {
	fakeProc(t, map[string]map[string]string{})
	s := newReg()
	s.acquireAcceptRA("ghost0") // must not panic
	s.releaseAcceptRA("ghost0")
}
