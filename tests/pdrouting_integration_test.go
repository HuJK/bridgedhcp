//go:build integration

package tests

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// sysctlGet reads one net.ipv6.conf value in the root namespace.
func sysctlGet(t *testing.T, iface, key string) string {
	t.Helper()
	out := run(t, "sysctl", "-n", "net.ipv6.conf."+iface+"."+key)
	return strings.TrimSpace(out)
}

// TestPDRouting drives routed-prefix mode end to end: stale-state cleanup
// at startup, rule/route installation on delegation, the RA-default
// mirror, full IP-state wipe on pd_lost, and sysctl restore on shutdown.
func TestPDRouting(t *testing.T) {
	const table = "9991"

	// uplink: bdup4 (root ns, PD client side) <-> wan4 (ns bdwan4, server)
	newNS(t, "bdwan4")
	veth(t, "bdup4", "wan4", "bdwan4")
	// served side: bdh5 <-> c5 (ns bdc5)
	newNS(t, "bdc5")
	veth(t, "bdh5", "c5", "bdc5")

	// Leftover guards: wipe table/rules no matter how the test ends.
	t.Cleanup(func() {
		for {
			out, _ := nsExecQuiet("", "ip", "-6", "rule", "show")
			if !strings.Contains(out, "lookup "+table) {
				break
			}
			runQuiet("ip", "-6", "rule", "del", "lookup", table)
		}
		runQuiet("ip", "-6", "route", "flush", "table", table)
	})

	delegated := netip.MustParsePrefix("fdaa:bb:cc:e0::/60")
	pdsrv := startMockPD(t, "bdwan4", "wan4", delegated, 5*time.Minute)
	_ = pdsrv

	// Crash leftovers from a "previous run": a rule and a route for an
	// old, different prefix on our table. Startup must wipe them.
	run(t, "ip", "-6", "rule", "add", "to", "fd00:dead::/64", "lookup", table, "priority", "5007")
	run(t, "ip", "-6", "route", "add", "fd00:dead::/64", "dev", "bdh5", "table", table)

	// A fake RA-learned default on the uplink for the mirror to pick up.
	run(t, "ip", "-6", "route", "add", "default", "via", "fe80::42", "dev", "bdup4", "proto", "ra", "metric", "424")

	// Originals for the restore assertions.
	origAcceptRA := sysctlGet(t, "bdup4", "accept_ra")
	origFwdUp := sysctlGet(t, "bdup4", "forwarding")
	origFwdBr := sysctlGet(t, "bdh5", "forwarding")
	run(t, "sysctl", "-qw", "net.ipv6.conf.bdup4.accept_ra=1")
	run(t, "sysctl", "-qw", "net.ipv6.conf.bdup4.forwarding=0")
	run(t, "sysctl", "-qw", "net.ipv6.conf.bdh5.forwarding=0")
	t.Cleanup(func() {
		runQuiet("sysctl", "-qw", "net.ipv6.conf.bdup4.accept_ra="+origAcceptRA)
		runQuiet("sysctl", "-qw", "net.ipv6.conf.bdup4.forwarding="+origFwdUp)
		runQuiet("sysctl", "-qw", "net.ipv6.conf.bdh5.forwarding="+origFwdBr)
	})

	cfg := map[string]any{
		"interfaces": []map[string]any{{
			"name":  "bdh5",
			"tag":   "it-pdroute",
			"slaac": true,
			"ra":    map[string]any{"interval": "2s"},
			"pd": map[string]any{
				"uplink":          "bdup4",
				"duid":            "00:03:00:01:02:00:00:00:ca:fe",
				"iaid":            5,
				"suffix":          "::1",
				"prefix_len":      64,
				"route_table":     9991,
				"rule_priority":   5005,
				"initial_timeout": "300ms",
				"max_timeout":     "1s",
				"attempts":        3,
			},
		}},
	}
	d := startDaemon(t, cfg)
	defer d.stop()

	// 1. delegation: event carries the route table, rules + routes appear
	ev := d.waitEvent("pd_prefix", 20*time.Second)
	if ev["route_table"] != float64(9991) {
		t.Fatalf("pd_prefix route_table = %v, want 9991", ev["route_table"])
	}
	const servedNet = "fdaa:bb:cc:e0::/64"
	waitFor(t, "policy rules", 5*time.Second, func() bool {
		out, _ := nsExecQuiet("", "ip", "-6", "rule", "show")
		return strings.Contains(out, "from "+servedNet+" lookup "+table) &&
			strings.Contains(out, "to "+servedNet+" lookup "+table)
	})
	waitFor(t, "subnet route in table", 5*time.Second, func() bool {
		out, _ := nsExecQuiet("", "ip", "-6", "route", "show", "table", table)
		return strings.Contains(out, servedNet) && strings.Contains(out, "dev bdh5")
	})
	waitFor(t, "mirrored RA default", 5*time.Second, func() bool {
		out, _ := nsExecQuiet("", "ip", "-6", "route", "show", "table", table)
		return strings.Contains(out, "default via fe80::42")
	})

	// ... and the crash leftovers are gone
	rules, _ := nsExecQuiet("", "ip", "-6", "rule", "show")
	if strings.Contains(rules, "fd00:dead::/64") {
		t.Fatal("stale rule survived startup cleanup")
	}
	routes, _ := nsExecQuiet("", "ip", "-6", "route", "show", "table", table)
	if strings.Contains(routes, "fd00:dead::/64") {
		t.Fatal("stale route survived startup cleanup")
	}

	// 2. sysctls: process lifetime, acquired now
	if got := sysctlGet(t, "bdup4", "accept_ra"); got != "2" {
		t.Fatalf("uplink accept_ra = %s, want 2", got)
	}
	if got := sysctlGet(t, "bdup4", "forwarding"); got != "1" {
		t.Fatalf("uplink forwarding = %s, want 1", got)
	}
	if got := sysctlGet(t, "bdh5", "forwarding"); got != "1" {
		t.Fatalf("bridge forwarding = %s, want 1", got)
	}

	// 3. RA-default mirror follows deletion
	run(t, "ip", "-6", "route", "del", "default", "via", "fe80::42", "dev", "bdup4", "proto", "ra", "metric", "424")
	waitFor(t, "mirrored default removed", 10*time.Second, func() bool {
		out, _ := nsExecQuiet("", "ip", "-6", "route", "show", "table", table)
		return !strings.Contains(out, "default via fe80::42")
	})
	run(t, "ip", "-6", "route", "add", "default", "via", "fe80::43", "dev", "bdup4", "proto", "ra", "metric", "424")
	waitFor(t, "mirrored default replaced", 10*time.Second, func() bool {
		out, _ := nsExecQuiet("", "ip", "-6", "route", "show", "table", table)
		return strings.Contains(out, "default via fe80::43")
	})

	// 4. pd_lost: every IP-derived object disappears, sysctls stay
	pdsrv.answering.Store(false)
	d.clearEvents()
	run(t, "ip", "link", "set", "bdup4", "down")
	time.Sleep(500 * time.Millisecond)
	run(t, "ip", "link", "set", "bdup4", "up")
	d.waitEvent("pd_lost", 60*time.Second)
	waitFor(t, "rules wiped on pd_lost", 10*time.Second, func() bool {
		out, _ := nsExecQuiet("", "ip", "-6", "rule", "show")
		return !strings.Contains(out, "lookup "+table)
	})
	waitFor(t, "table emptied on pd_lost", 10*time.Second, func() bool {
		out, _ := nsExecQuiet("", "ip", "-6", "route", "show", "table", table)
		return strings.TrimSpace(out) == ""
	})
	if got := sysctlGet(t, "bdup4", "accept_ra"); got != "2" {
		t.Fatalf("uplink accept_ra after pd_lost = %s, want 2 (process lifetime)", got)
	}

	// 5. shutdown: sysctls restored to what we set before the daemon ran
	d.stop()
	waitFor(t, "sysctls restored", 5*time.Second, func() bool {
		return sysctlGet(t, "bdup4", "accept_ra") == "1" &&
			sysctlGet(t, "bdup4", "forwarding") == "0" &&
			sysctlGet(t, "bdh5", "forwarding") == "0"
	})
}
