//go:build integration

// Integration harness: builds the real binary, wires veth pairs into
// network namespaces and runs protocol clients inside them.
package tests

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"
)

var binPath string

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Println("integration tests need root (netns); skipping")
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "bridgedhcp-it")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "bridgedhcp")
	build := exec.Command("go", "build", "-o", binPath, "github.com/HuJK/bridgedhcp/cmd/bridgedhcp")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Printf("build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// run executes a command, failing the test on error.
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// runQuiet executes a command ignoring failure.
func runQuiet(name string, args ...string) {
	_ = exec.Command(name, args...).Run()
}

// newNS creates a named network namespace, cleaned up with the test.
func newNS(t *testing.T, name string) {
	t.Helper()
	runQuiet("ip", "netns", "del", name)
	run(t, "ip", "netns", "add", name)
	t.Cleanup(func() { runQuiet("ip", "netns", "del", name) })
}

// veth creates hostIf in the root ns and peerIf inside ns, both up.
func veth(t *testing.T, hostIf, peerIf, ns string) {
	t.Helper()
	runQuiet("ip", "link", "del", hostIf)
	run(t, "ip", "link", "add", hostIf, "type", "veth", "peer", "name", peerIf)
	t.Cleanup(func() { runQuiet("ip", "link", "del", hostIf) })
	run(t, "ip", "link", "set", peerIf, "netns", ns)
	run(t, "ip", "link", "set", hostIf, "up")
	run(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	run(t, "ip", "netns", "exec", ns, "ip", "link", "set", peerIf, "up")
}

// nsExec runs a command inside a namespace.
func nsExec(t *testing.T, ns string, args ...string) string {
	t.Helper()
	return run(t, "ip", append([]string{"netns", "exec", ns}, args...)...)
}

// runInNS executes fn on a thread switched into the named namespace.
// Sockets created inside fn stay in that namespace. The OS thread is
// sacrificed (kept locked) so namespace pollution cannot leak.
func runInNS(t *testing.T, name string, fn func() error) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: thread dies with goroutine
		target, err := netns.GetFromName(name)
		if err != nil {
			errCh <- fmt.Errorf("netns %s: %w", name, err)
			return
		}
		defer target.Close()
		if err := netns.Set(target); err != nil {
			errCh <- err
			return
		}
		errCh <- fn()
	}()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

// daemon supervises one bridgedhcp instance and its event stream.
type daemon struct {
	t      *testing.T
	cmd    *exec.Cmd
	socket string
	key    string

	mu     sync.Mutex
	events []map[string]any
}

// startDaemon writes the config and launches the binary.
func startDaemon(t *testing.T, cfg map[string]any) *daemon {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "api.sock")
	key := "test-key-123"
	cfg["api_socket"] = socket
	cfg["api_key"] = key
	if _, ok := cfg["state_file"]; !ok {
		cfg["state_file"] = filepath.Join(dir, "state.json")
	}
	cfgPath := filepath.Join(dir, "config.json")
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	d := &daemon{t: t, socket: socket, key: key}
	d.cmd = exec.Command(binPath, "--config", cfgPath)
	stdout, err := d.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	d.cmd.Stderr = os.Stderr
	if err := d.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			var ev map[string]any
			if json.Unmarshal(sc.Bytes(), &ev) == nil {
				d.mu.Lock()
				d.events = append(d.events, ev)
				d.mu.Unlock()
			}
		}
	}()
	t.Cleanup(d.stop)
	d.waitEvent("ready", 10*time.Second)
	return d
}

func (d *daemon) stop() {
	if d.cmd.Process == nil {
		return
	}
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = d.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = d.cmd.Process.Kill()
		<-done
	}
}

// waitEvent blocks until an event of the given type arrived (including
// past events), failing the test on timeout.
func (d *daemon) waitEvent(typ string, timeout time.Duration) map[string]any {
	d.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		for _, ev := range d.events {
			if ev["event"] == typ {
				d.mu.Unlock()
				return ev
			}
		}
		d.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	d.t.Fatalf("event %q not seen within %s", typ, timeout)
	return nil
}

// hasEvent reports whether an event type was emitted so far.
func (d *daemon) hasEvent(typ string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, ev := range d.events {
		if ev["event"] == typ {
			return true
		}
	}
	return false
}

// clearEvents forgets past events (for phased assertions).
func (d *daemon) clearEvents() {
	d.mu.Lock()
	d.events = nil
	d.mu.Unlock()
}

// ctl invokes the binary's API client and returns stdout.
func (d *daemon) ctl(args ...string) string {
	d.t.Helper()
	full := append([]string{"ctl", "--socket", d.socket, "--key", d.key}, args...)
	out, err := exec.Command(binPath, full...).CombinedOutput()
	if err != nil {
		d.t.Fatalf("ctl %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// ctlIn invokes ctl with stdin.
func (d *daemon) ctlIn(stdin string, args ...string) string {
	d.t.Helper()
	full := append([]string{"ctl", "--socket", d.socket, "--key", d.key}, args...)
	cmd := exec.Command(binPath, full...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		d.t.Fatalf("ctl %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// waitFor polls cond until true or fatal timeout.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}
