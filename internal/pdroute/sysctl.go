package pdroute

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// sysctlBase is the /proc/sys mount; tests point it at a scratch tree.
var sysctlBase = "/proc/sys"

// sysctlReg is a refcounted sysctl setter shared by every Routes instance:
// several bridges may use the same uplink, and its accept_ra/forwarding
// must only be restored when the last user is gone. Restores are
// conditional — if someone else (netd) rewrote the value meanwhile, it is
// left alone.
type sysctlReg struct {
	mu      sync.Mutex
	entries map[string]*sysctlEntry
}

type sysctlEntry struct {
	refs int
	old  string // value found on first acquire
	set  string // value we wrote ("" = we changed nothing)
}

// sysctls is process-global so refcounts span all interfaces.
var sysctls = &sysctlReg{entries: map[string]*sysctlEntry{}}

func sysctlPath(iface, key string) string {
	return filepath.Join(sysctlBase, "net/ipv6/conf", iface, key)
}

// acquireAcceptRA relaxes accept_ra 1 -> 2 on iface so the kernel keeps
// accepting RAs (default route!) once the interface starts forwarding.
// 0 (RA disabled by the admin) and 2/3 are left untouched.
func (s *sysctlReg) acquireAcceptRA(iface string) {
	s.acquire(sysctlPath(iface, "accept_ra"), func(cur string) (string, bool) {
		return "2", cur == "1"
	})
}

// acquireForwarding enables per-interface forwarding (never all.forwarding:
// that would flip every interface — including cellular — into router mode
// and stop their RA processing).
func (s *sysctlReg) acquireForwarding(iface string) {
	s.acquire(sysctlPath(iface, "forwarding"), func(cur string) (string, bool) {
		return "1", cur == "0"
	})
}

func (s *sysctlReg) releaseAcceptRA(iface string) {
	s.release(sysctlPath(iface, "accept_ra"))
}

func (s *sysctlReg) releaseForwarding(iface string) {
	s.release(sysctlPath(iface, "forwarding"))
}

func (s *sysctlReg) acquire(path string, want func(cur string) (next string, change bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.entries[path]; e != nil {
		e.refs++
		return
	}
	e := &sysctlEntry{refs: 1}
	s.entries[path] = e
	cur, err := readSysctl(path)
	if err != nil {
		log.Printf("pdroute: read %s: %v", path, err)
		return
	}
	e.old = cur
	if next, change := want(cur); change && next != cur {
		if err := writeSysctl(path, next); err != nil {
			log.Printf("pdroute: write %s=%s: %v", path, next, err)
			return
		}
		e.set = next
	}
}

func (s *sysctlReg) release(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[path]
	if e == nil {
		return
	}
	e.refs--
	if e.refs > 0 {
		return
	}
	delete(s.entries, path)
	if e.set == "" || e.set == e.old {
		return
	}
	// Restore only if the value is still ours; a concurrent change by
	// netd/admin wins.
	cur, err := readSysctl(path)
	if err != nil || cur != e.set {
		return
	}
	if err := writeSysctl(path, e.old); err != nil {
		log.Printf("pdroute: restore %s=%s: %v", path, e.old, err)
	}
}

func readSysctl(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func writeSysctl(path, v string) error {
	return os.WriteFile(path, []byte(v), 0o644)
}
