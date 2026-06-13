package pd

import (
	"net/netip"
	"testing"
)

func noopCallback(netip.Prefix, bool) {}

// Renew is Wakeup with intent: it must leave a pending signal on the wake
// channel so a sleeping run loop retries immediately.
func TestRenewSignalsWake(t *testing.T) {
	c := New(Config{Uplink: "lo"}, noopCallback)
	select { // drain any pre-existing token (defensive)
	case <-c.wake:
	default:
	}
	c.Renew()
	select {
	case <-c.wake:
	default:
		t.Fatal("Renew did not signal the wake channel")
	}
}

// Release records the request and signals wake; with no held delegation,
// maybeRelease consumes the request as a no-op (nothing to RELEASE) and does
// not touch the socket.
func TestReleaseNoBindingIsNoOp(t *testing.T) {
	c := New(Config{Uplink: "lo"}, noopCallback)
	c.Release()

	c.mu.Lock()
	req := c.releaseReq
	c.mu.Unlock()
	if !req {
		t.Fatal("Release did not set releaseReq")
	}

	// nil conn is safe: with no binding, maybeRelease returns before any
	// socket use.
	if c.maybeRelease(nil) {
		t.Fatal("maybeRelease acted with no held delegation")
	}
	c.mu.Lock()
	req = c.releaseReq
	c.mu.Unlock()
	if req {
		t.Fatal("maybeRelease did not consume the release request")
	}
}

// takeReleaseReq returns the pending flag exactly once.
func TestTakeReleaseReqOnce(t *testing.T) {
	c := New(Config{Uplink: "lo"}, noopCallback)
	if c.takeReleaseReq() {
		t.Fatal("fresh client reported a pending release")
	}
	c.mu.Lock()
	c.releaseReq = true
	c.mu.Unlock()
	if !c.takeReleaseReq() {
		t.Fatal("takeReleaseReq did not return the set flag")
	}
	if c.takeReleaseReq() {
		t.Fatal("takeReleaseReq returned the flag twice")
	}
}
