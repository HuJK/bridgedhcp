//go:build integration

package tests

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/nclient6"
)

// ---- scenario 1: DHCPv4 end to end, static leases via API, persistence ----

func TestDHCPv4EndToEnd(t *testing.T) {
	newNS(t, "bdc0")
	veth(t, "bdh0", "c0", "bdc0")
	run(t, "ip", "addr", "add", "192.168.77.1/24", "dev", "bdh0")

	stateDir := t.TempDir()
	cfg := map[string]any{
		"state_file": stateDir + "/state.json",
		"interfaces": []map[string]any{{
			"name":    "bdh0",
			"tag":     "it-v4",
			"prefix4": "192.168.77.1/24",
			"dhcp4": map[string]any{
				"pool_offset_start": 100,
				"pool_offset_end":   150,
				"lease_time":        "1h",
				"dns":               []string{"192.168.77.1"},
			},
		}},
	}
	d := startDaemon(t, cfg)
	d.waitEvent("attached", 5*time.Second)

	// full DORA handshake from inside the client namespace
	var leasedIP netip.Addr
	runInNS(t, "bdc0", func() error {
		c, err := nclient4.New("c0")
		if err != nil {
			return err
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		lease, err := c.Request(ctx)
		if err != nil {
			return err
		}
		ip, _ := netip.AddrFromSlice(lease.ACK.YourIPAddr.To4())
		leasedIP = ip
		if r := lease.ACK.Router(); len(r) == 0 || r[0].String() != "192.168.77.1" {
			return fmt.Errorf("router option: %v", r)
		}
		if dns := lease.ACK.DNS(); len(dns) == 0 || dns[0].String() != "192.168.77.1" {
			return fmt.Errorf("dns option: %v", dns)
		}
		return nil
	})
	lo := netip.MustParseAddr("192.168.77.100")
	hi := netip.MustParseAddr("192.168.77.150")
	if leasedIP.Less(lo) || hi.Less(leasedIP) {
		t.Fatalf("lease %s outside pool", leasedIP)
	}

	// the API sees the lease
	var leases struct {
		Leases []struct {
			IP  string `json:"ip"`
			MAC string `json:"mac"`
		} `json:"leases"`
	}
	if err := json.Unmarshal([]byte(d.ctl("leases", "bdh0", "4")), &leases); err != nil {
		t.Fatal(err)
	}
	if len(leases.Leases) != 1 || leases.Leases[0].IP != leasedIP.String() {
		t.Fatalf("api leases: %+v", leases)
	}

	// install a static binding for the client's MAC, release, re-acquire:
	// the client must now get base+5
	var mac string
	runInNS(t, "bdc0", func() error {
		ifi, err := net.InterfaceByName("c0")
		if err != nil {
			return err
		}
		mac = ifi.HardwareAddr.String()
		return nil
	})
	d.ctlIn(fmt.Sprintf(`{"id":"it-vm","mac":"%s","offset":5}`, mac),
		"static-put", "bdh0", "4")
	d.ctl("lease-del", "bdh0", leasedIP.String())

	runInNS(t, "bdc0", func() error {
		c, err := nclient4.New("c0")
		if err != nil {
			return err
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		lease, err := c.Request(ctx)
		if err != nil {
			return err
		}
		got := lease.ACK.YourIPAddr.String()
		if got != "192.168.77.5" {
			return fmt.Errorf("static lease: got %s want 192.168.77.5", got)
		}
		return nil
	})

	// persistence: restart the daemon with the same state file — the
	// static binding and the active lease must survive
	d.stop()
	d2 := startDaemon(t, cfg)
	defer d2.stop()
	out := d2.ctl("leases", "bdh0", "4")
	if !strings.Contains(out, "192.168.77.5") {
		t.Fatalf("lease lost across restart: %s", out)
	}
	status := d2.ctl("status")
	if !strings.Contains(status, "it-vm") {
		t.Fatalf("static binding lost across restart: %s", status)
	}
}

// ---- scenario 2: SLAAC — the client kernel autoconfigures from our RA ----

func TestSLAACKernelAutoconf(t *testing.T) {
	newNS(t, "bdc1")
	veth(t, "bdh1", "c1", "bdc1")
	nsExec(t, "bdc1", "sysctl", "-qw",
		"net.ipv6.conf.c1.accept_ra=1", "net.ipv6.conf.c1.autoconf=1")
	run(t, "ip", "addr", "add", "fd71::1/64", "dev", "bdh1")

	cfg := map[string]any{
		"interfaces": []map[string]any{{
			"name":    "bdh1",
			"prefix6": "fd71::1/64",
			"slaac":   true,
			"ra":      map[string]any{"interval": "2s"},
		}},
	}
	d := startDaemon(t, cfg)
	defer d.stop()
	d.waitEvent("attached", 5*time.Second)

	waitFor(t, "SLAAC address in client ns", 20*time.Second, func() bool {
		out, err := nsExecQuiet("bdc1", "ip", "-6", "addr", "show", "dev", "c1")
		return err == nil && strings.Contains(out, "fd71:") &&
			strings.Contains(out, "dynamic")
	})
}

// ---- scenario 3: stateful DHCPv6 ----

func TestDHCPv6Stateful(t *testing.T) {
	newNS(t, "bdc2")
	veth(t, "bdh2", "c2", "bdc2")
	run(t, "ip", "addr", "add", "fd72::1/64", "dev", "bdh2")

	cfg := map[string]any{
		"interfaces": []map[string]any{{
			"name":    "bdh2",
			"prefix6": "fd72::1/64",
			"dhcp6": map[string]any{
				"pool_offset_start": 256,
				"pool_offset_end":   511,
				"lease_time":        "1h",
				"dns":               []string{"fd72::1"},
			},
			"ra": map[string]any{"interval": "2s"},
		}},
	}
	d := startDaemon(t, cfg)
	defer d.stop()
	d.waitEvent("attached", 5*time.Second)

	// the client needs a link-local address before nclient6 can bind
	waitForLinkLocal(t, "bdc2", "c2")

	var got netip.Addr
	runInNS(t, "bdc2", func() error {
		c, err := nclient6.New("c2")
		if err != nil {
			return err
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		adv, err := c.Solicit(ctx)
		if err != nil {
			return err
		}
		reply, err := c.Request(ctx, adv)
		if err != nil {
			return err
		}
		ia := reply.Options.OneIANA()
		if ia == nil || len(ia.Options.Addresses()) == 0 {
			return fmt.Errorf("no IA_NA address in reply")
		}
		got, _ = netip.AddrFromSlice(ia.Options.Addresses()[0].IPv6Addr)
		return nil
	})
	lo := netip.MustParseAddr("fd72::100")
	hi := netip.MustParseAddr("fd72::1ff")
	if got.Less(lo) || hi.Less(got) {
		t.Fatalf("IA_NA %s outside pool [%s, %s]", got, lo, hi)
	}
	out := d.ctl("leases", "bdh2", "6")
	if !strings.Contains(out, got.String()) {
		t.Fatalf("v6 lease not in API: %s", out)
	}
}

// ---- scenario 4: PD acquire, roam-keep, loss-withdraw ----

func TestPDLifecycle(t *testing.T) {
	// uplink: bdup0 (root ns, PD client side) <-> wan0 (ns bdwan, server)
	newNS(t, "bdwan")
	veth(t, "bdup0", "wan0", "bdwan")
	// serving side: bdh3 <-> c3 (ns bdc3) to observe RA of the PD prefix
	newNS(t, "bdc3")
	veth(t, "bdh3", "c3", "bdc3")
	nsExec(t, "bdc3", "sysctl", "-qw",
		"net.ipv6.conf.c3.accept_ra=1", "net.ipv6.conf.c3.autoconf=1")

	delegated := netip.MustParsePrefix("fdaa:bb:cc:d0::/60")
	pdsrv := startMockPD(t, "bdwan", "wan0", delegated, 5*time.Minute)

	cfg := map[string]any{
		"interfaces": []map[string]any{{
			"name":  "bdh3",
			"tag":   "it-pd",
			"slaac": true,
			"ra":    map[string]any{"interval": "2s"},
			"pd": map[string]any{
				"uplink":          "bdup0",
				"duid":            "00:03:00:01:02:00:00:00:be:ef",
				"iaid":            3,
				"suffix":          "::1",
				"prefix_len":      64,
				"initial_timeout": "300ms",
				"max_timeout":     "1s",
				"attempts":        3,
			},
		}},
	}
	d := startDaemon(t, cfg)
	defer d.stop()

	// 1. acquire: address fdaa:bb:cc:d0::1/64 appears on bdh3
	ev := d.waitEvent("pd_prefix", 20*time.Second)
	if ev["address"] != "fdaa:bb:cc:d0::1/64" {
		t.Fatalf("pd address %v", ev["address"])
	}
	waitFor(t, "PD address on bdh3", 5*time.Second, func() bool {
		out, _ := nsExecQuiet("", "ip", "-6", "addr", "show", "dev", "bdh3")
		return strings.Contains(out, "fdaa:bb:cc:d0::1/64")
	})
	// ... and the client namespace autoconfigures from the delegated /64
	waitFor(t, "client SLAAC from PD prefix", 20*time.Second, func() bool {
		out, err := nsExecQuiet("bdc3", "ip", "-6", "addr", "show", "dev", "c3")
		return err == nil && strings.Contains(out, "fdaa:bb:cc:d0:")
	})

	// 2. roam-keep: flap the uplink (same L2, server still there). The
	// client must confirm via RENEW/REBIND — no pd_lost, prefix kept.
	d.clearEvents()
	pdsrv.resetSeen()
	run(t, "ip", "link", "set", "bdup0", "down")
	time.Sleep(500 * time.Millisecond)
	run(t, "ip", "link", "set", "bdup0", "up")
	waitFor(t, "confirm after roam", 20*time.Second, func() bool {
		return pdsrv.sawType(dhcpv6.MessageTypeRenew) || pdsrv.sawType(dhcpv6.MessageTypeRebind)
	})
	time.Sleep(2 * time.Second) // give a failure window to surface
	if d.hasEvent("pd_lost") {
		t.Fatal("roam within the same network dropped the prefix")
	}
	if pdsrv.sawType(dhcpv6.MessageTypeSolicit) {
		t.Fatal("roam re-solicited instead of confirming")
	}
	out := run(t, "ip", "-6", "addr", "show", "dev", "bdh3")
	if !strings.Contains(out, "fdaa:bb:cc:d0::1/64") {
		t.Fatal("PD address lost during roam")
	}

	// 3. release-reacquire: the API release sends a RELEASE to the server,
	// drops the prefix, then re-solicits a fresh one (the same prefix here).
	d.clearEvents()
	pdsrv.resetSeen()
	d.ctl("pd-release", "bdh3")
	waitFor(t, "RELEASE sent to server", 10*time.Second, func() bool {
		return pdsrv.sawType(dhcpv6.MessageTypeRelease)
	})
	if ev := d.waitEvent("pd_prefix", 20*time.Second); ev["address"] != "fdaa:bb:cc:d0::1/64" {
		t.Fatalf("re-acquired pd address %v", ev["address"])
	}
	if !pdsrv.sawType(dhcpv6.MessageTypeSolicit) {
		t.Fatal("release did not re-solicit a fresh delegation")
	}
	waitFor(t, "PD address back on bdh3", 5*time.Second, func() bool {
		out, _ := nsExecQuiet("", "ip", "-6", "addr", "show", "dev", "bdh3")
		return strings.Contains(out, "fdaa:bb:cc:d0::1/64")
	})

	// 4. loss-withdraw: the new network has no PD server. Confirmation
	// fails -> prefix withdrawn, address removed.
	pdsrv.answering.Store(false)
	d.clearEvents()
	run(t, "ip", "link", "set", "bdup0", "down")
	time.Sleep(500 * time.Millisecond)
	run(t, "ip", "link", "set", "bdup0", "up")
	d.waitEvent("pd_lost", 60*time.Second)
	waitFor(t, "PD address removed", 10*time.Second, func() bool {
		out, _ := nsExecQuiet("", "ip", "-6", "addr", "show", "dev", "bdh3")
		return !strings.Contains(out, "fdaa:bb:cc:d0::1/64")
	})
}

// ---- scenario 4b: untagged domain on a real bridge (VLAN 0 semantics) ----
//
// The served interface is a kernel bridge that doubles as trunk backbone.
// Untagged clients must be served; a *tagged* client's DHCP — whose 802.1q
// tag the kernel strips into skb metadata before socket filters run —
// must NOT be answered by the untagged domain's server.

func TestUntaggedDomainOnBridge(t *testing.T) {
	newNS(t, "bdc5")
	veth(t, "bdp5", "c5", "bdc5")
	runQuiet("ip", "link", "del", "bdbr5")
	run(t, "ip", "link", "add", "bdbr5", "type", "bridge")
	t.Cleanup(func() { runQuiet("ip", "link", "del", "bdbr5") })
	run(t, "ip", "link", "set", "bdp5", "master", "bdbr5")
	run(t, "ip", "link", "set", "bdbr5", "up")
	run(t, "ip", "addr", "add", "192.168.79.1/24", "dev", "bdbr5")

	cfg := map[string]any{
		"interfaces": []map[string]any{{
			"name":    "bdbr5",
			"tag":     "vlan0",
			"prefix4": "192.168.79.1/24",
			"dhcp4": map[string]any{
				"pool_offset_start": 100,
				"pool_offset_end":   150,
				"lease_time":        "1h",
			},
		}},
	}
	d := startDaemon(t, cfg)
	defer d.stop()
	d.waitEvent("attached", 5*time.Second)

	// untagged client on the bridge: served
	runInNS(t, "bdc5", func() error {
		c, err := nclient4.New("c5")
		if err != nil {
			return err
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		lease, err := c.Request(ctx)
		if err != nil {
			return fmt.Errorf("untagged client not served: %w", err)
		}
		if !strings.HasPrefix(lease.ACK.YourIPAddr.String(), "192.168.79.") {
			return fmt.Errorf("lease %s outside untagged subnet", lease.ACK.YourIPAddr)
		}
		return nil
	})

	// tagged client (VLAN 30 subinterface): must stay unanswered
	nsExec(t, "bdc5", "ip", "link", "add", "link", "c5", "name", "c5.30",
		"type", "vlan", "id", "30")
	nsExec(t, "bdc5", "ip", "link", "set", "c5.30", "up")
	runInNS(t, "bdc5", func() error {
		c, err := nclient4.New("c5.30")
		if err != nil {
			return err
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if lease, err := c.Request(ctx); err == nil {
			return fmt.Errorf(
				"tagged VLAN 30 client was answered by the untagged server (%s)",
				lease.ACK.YourIPAddr)
		}
		return nil
	})
}

// ---- scenario 5: DNS forwarder + port-53 REDIRECT ----

func TestDNSForwarderAndRedirect(t *testing.T) {
	if _, err := nsExecQuiet("", "iptables", "-t", "nat", "-S"); err != nil {
		t.Skip("no iptables nat support on this host")
	}
	newNS(t, "bdc4")
	veth(t, "bdh4", "c4", "bdc4")
	run(t, "ip", "addr", "add", "192.168.78.1/24", "dev", "bdh4")
	nsExec(t, "bdc4", "ip", "addr", "add", "192.168.78.2/24", "dev", "c4")

	upstream := startMockDNS(t)
	cfg := map[string]any{
		"interfaces": []map[string]any{{
			"name":    "bdh4",
			"prefix4": "192.168.78.1/24",
			"dns": map[string]any{
				"port":        5355,
				"redirect_53": true,
				"upstream":    "static",
				"upstreams":   []string{upstream},
			},
		}},
	}
	d := startDaemon(t, cfg)
	defer d.stop()
	d.waitEvent("dns_ready", 10*time.Second)

	query := func(port int) error {
		var rerr error
		runInNS(t, "bdc4", func() error {
			conn, err := net.Dial("udp", fmt.Sprintf("192.168.78.1:%d", port))
			if err != nil {
				return err
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			q := testQuery(0x4242, "vm.guest.test")
			if _, err := conn.Write(q); err != nil {
				return err
			}
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				rerr = fmt.Errorf("port %d: %w", port, err)
				return nil
			}
			ans := buf[:n]
			if ans[0] != q[0] || ans[1] != q[1] || ans[2]&0x80 == 0 {
				rerr = fmt.Errorf("port %d: malformed answer", port)
			}
			return nil
		})
		return rerr
	}

	// direct port and the REDIRECTed :53 both answer
	if err := query(5355); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "dnat rule", 10*time.Second, func() bool {
		out, _ := nsExecQuiet("", "iptables", "-t", "nat", "-S", "PREROUTING")
		return strings.Contains(out, "--to-ports 5355")
	})
	if err := query(53); err != nil {
		t.Fatal(err)
	}
}

// ---- helpers ----

// nsExecQuiet runs in a namespace ("" = root ns) returning output+error.
func nsExecQuiet(ns string, args ...string) (string, error) {
	if ns != "" {
		args = append([]string{"netns", "exec", ns}, args...)
		out, err := exec.Command("ip", args...).CombinedOutput()
		return string(out), err
	}
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out), err
}

// waitForLinkLocal waits until the iface in ns has a usable (non-tentative)
// link-local address.
func waitForLinkLocal(t *testing.T, ns, iface string) {
	t.Helper()
	waitFor(t, "link-local on "+iface, 10*time.Second, func() bool {
		out, err := nsExecQuiet(ns, "ip", "-6", "addr", "show", "dev", iface, "scope", "link")
		return err == nil && strings.Contains(out, "fe80:") && !strings.Contains(out, "tentative")
	})
}

// startMockDNS runs a UDP DNS responder on the host loopback answering
// everything with one A record.
func startMockDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			out := append([]byte(nil), buf[:n]...)
			out[2] |= 0x80
			binary.BigEndian.PutUint16(out[6:8], 1)
			out = append(out, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1)
			_, _ = pc.WriteTo(out, peer)
		}
	}()
	return pc.LocalAddr().String()
}

// testQuery crafts a minimal A query.
func testQuery(txid uint16, name string) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], txid)
	q[2] = 0x01
	binary.BigEndian.PutUint16(q[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	return q
}
