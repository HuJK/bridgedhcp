package server

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"

	"github.com/HuJK/bridgedhcp/internal/packet"
)

// testEnv is a fixed-world env with a frame capture buffer.
type testEnv struct {
	mu     sync.Mutex
	frames [][]byte

	v4p   netip.Prefix
	v6p   netip.Prefix
	v6s   []netip.Prefix
	ll    netip.Addr
	done  chan struct{}
	close sync.Once
}

func newTestEnv() *testEnv {
	return &testEnv{
		v4p:  netip.MustParsePrefix("192.168.50.1/24"),
		v6p:  netip.MustParsePrefix("fd50::1/64"),
		v6s:  []netip.Prefix{netip.MustParsePrefix("fd50::1/64")},
		ll:   netip.MustParseAddr("fe80::1"),
		done: make(chan struct{}),
	}
}

func (e *testEnv) env() *env {
	return &env{
		name:      "test0",
		mac:       func() net.HardwareAddr { return net.HardwareAddr{2, 0, 0, 0, 0, 1} },
		v4:        func() (netip.Prefix, bool) { return e.v4p, e.v4p.IsValid() },
		v6:        func() (netip.Prefix, bool) { return e.v6p, e.v6p.IsValid() },
		v6all:     func() []netip.Prefix { e.mu.Lock(); defer e.mu.Unlock(); return e.v6s },
		linkLocal: func() netip.Addr { return e.ll },
		write: func(f []byte) error {
			e.mu.Lock()
			e.frames = append(e.frames, append([]byte(nil), f...))
			e.mu.Unlock()
			return nil
		},
		done: e.done,
	}
}

func (e *testEnv) take() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.frames
	e.frames = nil
	return out
}

func (e *testEnv) stop() { e.close.Do(func() { close(e.done) }) }

func ingress4(t *testing.T, req *dhcpv4.DHCPv4, srcMAC net.HardwareAddr) packet.Ingress {
	t.Helper()
	frame := packet.CraftUDP4(srcMAC, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		net.IPv4zero, net.IPv4bcast, 68, 67, req.ToBytes())
	pkt, ok := packet.Parse(frame)
	if !ok {
		t.Fatal("ingress parse failed")
	}
	return pkt
}

func reply4(t *testing.T, frames [][]byte) *dhcpv4.DHCPv4 {
	t.Helper()
	if len(frames) != 1 {
		t.Fatalf("want 1 reply frame, got %d", len(frames))
	}
	pkt, ok := packet.Parse(frames[0])
	if !ok || !pkt.IsUDP4 {
		t.Fatal("reply not udp4")
	}
	msg, err := dhcpv4.FromBytes(pkt.Payload)
	if err != nil {
		t.Fatalf("reply decode: %v", err)
	}
	return msg
}

func discover(t *testing.T, mac net.HardwareAddr, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	t.Helper()
	d, err := dhcpv4.NewDiscovery(mac, mods...)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDHCP4DiscoverOfferRequestAck(t *testing.T) {
	te := newTestEnv()
	defer te.stop()
	s := newDHCP4Server(te.env(), DHCP4Config{
		Enabled: true, PoolOffsetStart: 100, PoolOffsetEnd: 110, LeaseTime: time.Hour,
	})

	mac := net.HardwareAddr{2, 0, 0, 0, 0, 0x42}
	if !s.handleFrame(ingress4(t, discover(t, mac), mac)) {
		t.Fatal("discover not consumed")
	}
	offer := reply4(t, te.take())
	if offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("want offer, got %s", offer.MessageType())
	}
	ip, _ := netip.AddrFromSlice(offer.YourIPAddr.To4())
	if ip != netip.MustParseAddr("192.168.50.100") {
		t.Fatalf("offer ip %s", ip)
	}
	if got := offer.Router(); len(got) == 0 || !got[0].Equal(net.ParseIP("192.168.50.1").To4()) {
		t.Fatalf("router option %v", got)
	}

	req, err := dhcpv4.NewRequestFromOffer(offer)
	if err != nil {
		t.Fatal(err)
	}
	s.handleFrame(ingress4(t, req, mac))
	ack := reply4(t, te.take())
	if ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("want ack, got %s", ack.MessageType())
	}

	leases := s.Leases()
	if len(leases) != 1 || leases[0].IP != ip || leases[0].MAC != mac.String() {
		t.Fatalf("leases %+v", leases)
	}
}

func TestDHCP4StaticBindingByOffset(t *testing.T) {
	te := newTestEnv()
	defer te.stop()
	s := newDHCP4Server(te.env(), DHCP4Config{
		Enabled: true, PoolOffsetStart: 100, PoolOffsetEnd: 110, LeaseTime: time.Hour,
	})
	mac := "02:00:00:00:00:55"
	if err := s.PutStatic(StaticBinding{ID: "vm1", MAC: &mac, Offset: 7}); err != nil {
		t.Fatal(err)
	}

	hw, _ := net.ParseMAC(mac)
	s.handleFrame(ingress4(t, discover(t, hw), hw))
	offer := reply4(t, te.take())
	ip, _ := netip.AddrFromSlice(offer.YourIPAddr.To4())
	if ip != netip.MustParseAddr("192.168.50.7") {
		t.Fatalf("static offer ip %s, want .7", ip)
	}
}

func TestDHCP4NakOnWrongAddress(t *testing.T) {
	te := newTestEnv()
	defer te.stop()
	s := newDHCP4Server(te.env(), DHCP4Config{
		Enabled: true, PoolOffsetStart: 100, PoolOffsetEnd: 110, LeaseTime: time.Hour,
	})
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 0x43}
	req := discover(t, mac, dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("10.9.9.9"))))
	s.handleFrame(ingress4(t, req, mac))
	nak := reply4(t, te.take())
	if nak.MessageType() != dhcpv4.MessageTypeNak {
		t.Fatalf("want nak, got %s", nak.MessageType())
	}
}

func TestDHCP4PoolExhaustionSilent(t *testing.T) {
	te := newTestEnv()
	defer te.stop()
	s := newDHCP4Server(te.env(), DHCP4Config{
		Enabled: true, PoolOffsetStart: 100, PoolOffsetEnd: 101, LeaseTime: time.Hour,
	})
	for i := byte(1); i <= 2; i++ {
		mac := net.HardwareAddr{2, 0, 0, 0, 1, i}
		s.handleFrame(ingress4(t, discover(t, mac), mac))
		te.take()
	}
	mac := net.HardwareAddr{2, 0, 0, 0, 1, 9}
	s.handleFrame(ingress4(t, discover(t, mac), mac))
	if frames := te.take(); len(frames) != 0 {
		t.Fatalf("exhausted pool answered with %d frames", len(frames))
	}
}

func TestDHCP4SameClientKeepsLease(t *testing.T) {
	te := newTestEnv()
	defer te.stop()
	s := newDHCP4Server(te.env(), DHCP4Config{
		Enabled: true, PoolOffsetStart: 100, PoolOffsetEnd: 110, LeaseTime: time.Hour,
	})
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 0x66}
	s.handleFrame(ingress4(t, discover(t, mac), mac))
	first := reply4(t, te.take()).YourIPAddr.String()
	s.handleFrame(ingress4(t, discover(t, mac), mac))
	second := reply4(t, te.take()).YourIPAddr.String()
	if first != second {
		t.Fatalf("lease churn: %s then %s", first, second)
	}
}

// --- DHCPv6 ---

func ingress6(t *testing.T, msg *dhcpv6.Message, srcMAC net.HardwareAddr, srcIP string) packet.Ingress {
	t.Helper()
	frame := packet.CraftUDP6(srcMAC, net.HardwareAddr{0x33, 0x33, 0, 1, 0, 2},
		net.ParseIP(srcIP), net.ParseIP("ff02::1:2"), 546, 547, msg.ToBytes())
	pkt, ok := packet.Parse(frame)
	if !ok {
		t.Fatal("ingress6 parse failed")
	}
	return pkt
}

func reply6(t *testing.T, frames [][]byte) *dhcpv6.Message {
	t.Helper()
	if len(frames) != 1 {
		t.Fatalf("want 1 reply frame, got %d", len(frames))
	}
	pkt, ok := packet.Parse(frames[0])
	if !ok || !pkt.IsUDP6 {
		t.Fatal("reply not udp6")
	}
	parsed, err := dhcpv6.FromBytes(pkt.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.(*dhcpv6.Message)
}

func TestDHCP6SolicitAdvertiseRequestReply(t *testing.T) {
	te := newTestEnv()
	defer te.stop()
	s := newDHCP6Server(te.env(), DHCP6Config{
		Enabled: true, PoolOffsetStart: 0x100, PoolOffsetEnd: 0x1FF, LeaseTime: time.Hour,
	})

	mac := net.HardwareAddr{2, 0, 0, 0, 0, 0x77}
	duid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: mac}
	sol, err := dhcpv6.NewSolicit(mac)
	if err != nil {
		t.Fatal(err)
	}
	s.handleFrame(ingress6(t, sol, mac, "fe80::77"))
	adv := reply6(t, te.take())
	if adv.MessageType != dhcpv6.MessageTypeAdvertise {
		t.Fatalf("want advertise, got %s", adv.MessageType)
	}
	iana1 := adv.Options.OneIANA()
	if iana1 == nil || len(iana1.Options.Addresses()) == 0 {
		t.Fatal("advertise carries no address")
	}
	got, _ := netip.AddrFromSlice(iana1.Options.Addresses()[0].IPv6Addr)
	if got != netip.MustParseAddr("fd50::100") {
		t.Fatalf("advertised %s, want fd50::100", got)
	}
	if iana1.IaId != sol.Options.OneIANA().IaId {
		t.Fatal("IAID not preserved")
	}

	reqMsg, err := dhcpv6.NewRequestFromAdvertise(adv)
	if err != nil {
		t.Fatal(err)
	}
	s.handleFrame(ingress6(t, reqMsg, mac, "fe80::77"))
	rep := reply6(t, te.take())
	if rep.MessageType != dhcpv6.MessageTypeReply {
		t.Fatalf("want reply, got %s", rep.MessageType)
	}
	leases := s.Leases()
	if len(leases) != 1 || leases[0].IP != got {
		t.Fatalf("leases %+v", leases)
	}
	_ = duid
}

func TestDHCP6SilentWithoutPrefix(t *testing.T) {
	te := newTestEnv()
	te.v6p = netip.Prefix{} // PD not yet acquired
	defer te.stop()
	s := newDHCP6Server(te.env(), DHCP6Config{
		Enabled: true, PoolOffsetStart: 0x100, PoolOffsetEnd: 0x1FF,
	})
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 0x78}
	sol, _ := dhcpv6.NewSolicit(mac)
	if !s.handleFrame(ingress6(t, sol, mac, "fe80::78")) {
		t.Fatal("dhcpv6 frame not consumed")
	}
	if frames := te.take(); len(frames) != 0 {
		t.Fatal("answered without a prefix")
	}
}

// --- RA ---

func TestRASolicitedAndDeprecation(t *testing.T) {
	te := newTestEnv()
	defer te.stop()
	cfg := RAConfig{Enabled: true, Autonomous: true, Interval: time.Hour}
	cfg.normalize()
	s := newRAServer(te.env(), cfg)
	time.Sleep(50 * time.Millisecond) // initial periodic RA
	te.take()

	// solicited RA carries the live prefix with nonzero lifetimes
	rs := []byte{packet.ICMPv6TypeRouterSolicit, 0, 0, 0, 0, 0, 0, 0}
	frame := packet.CraftICMP6(net.HardwareAddr{2, 0, 0, 0, 0, 9},
		net.HardwareAddr{0x33, 0x33, 0, 0, 0, 2},
		net.ParseIP("fe80::9"), net.ParseIP("ff02::2"), rs, 255)
	pkt, _ := packet.Parse(frame)
	if !s.handleFrame(pkt) {
		t.Fatal("RS not consumed")
	}
	ra := findRA(t, te.take())
	valid, found := prefixLifetime(ra, "fd50::")
	if !found || valid == 0 {
		t.Fatalf("live prefix missing or zero lifetime (found=%v valid=%d)", found, valid)
	}

	// drop the prefix: next RA must advertise it with zero lifetime
	te.mu.Lock()
	te.v6s = nil
	te.mu.Unlock()
	s.handleFrame(pkt)
	ra = findRA(t, te.take())
	valid, found = prefixLifetime(ra, "fd50::")
	if !found || valid != 0 {
		t.Fatalf("withdrawn prefix not deprecated (found=%v valid=%d)", found, valid)
	}
}

// findRA returns the ICMPv6 body of the single RA frame.
func findRA(t *testing.T, frames [][]byte) []byte {
	t.Helper()
	if len(frames) != 1 {
		t.Fatalf("want 1 RA frame, got %d", len(frames))
	}
	pkt, ok := packet.Parse(frames[0])
	if !ok || !pkt.IsICMP6 || pkt.ICMPTyp != packet.ICMPv6TypeRouterAdvert {
		t.Fatal("not an RA")
	}
	return pkt.Payload
}

// prefixLifetime walks RA options for a prefix-information option whose
// prefix has the given string prefix, returning its valid lifetime.
func prefixLifetime(ra []byte, prefixStr string) (uint32, bool) {
	opts := ra[16:]
	for len(opts) >= 8 {
		typ, ln := opts[0], int(opts[1])*8
		if ln == 0 || ln > len(opts) {
			break
		}
		if typ == 3 && ln == 32 {
			addr, _ := netip.AddrFromSlice(opts[16:32])
			if len(addr.String()) >= len(prefixStr) && addr.String()[:len(prefixStr)] == prefixStr {
				return uint32(opts[4])<<24 | uint32(opts[5])<<16 | uint32(opts[6])<<8 | uint32(opts[7]), true
			}
		}
		opts = opts[ln:]
	}
	return 0, false
}

// --- offsets ---

func TestAddrAtOffset(t *testing.T) {
	cases := []struct {
		prefix string
		offset uint64
		want   string
	}{
		{"192.168.1.1/24", 5, "192.168.1.5"},
		{"192.168.1.99/24", 200, "192.168.1.200"},
		{"10.0.0.1/8", 1 << 16, "10.1.0.0"},
		{"fd00::1/64", 0x1234, "fd00::1234"},
	}
	for _, c := range cases {
		got := addrAtOffset(netip.MustParsePrefix(c.prefix), c.offset)
		if got.String() != c.want {
			t.Errorf("addrAtOffset(%s, %d) = %s, want %s", c.prefix, c.offset, got, c.want)
		}
	}
	// offset escaping the prefix is invalid
	if got := addrAtOffset(netip.MustParsePrefix("192.168.1.1/24"), 300); got.IsValid() {
		t.Errorf("out-of-prefix offset returned %s", got)
	}
}
