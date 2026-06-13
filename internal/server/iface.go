package server

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/HuJK/bridgedhcp/internal/dnsfwd"
	"github.com/HuJK/bridgedhcp/internal/ifwatch"
	"github.com/HuJK/bridgedhcp/internal/packet"
	"github.com/HuJK/bridgedhcp/internal/pd"
	"github.com/HuJK/bridgedhcp/internal/pdroute"
	"github.com/HuJK/bridgedhcp/internal/transport"
)

// PDConfig enables prefix delegation for one served interface.
type PDConfig struct {
	Uplink    string
	DUID      []byte
	IAID      uint32
	Suffix    netip.Addr // OR-ed into the delegated prefix base, e.g. ::1
	PrefixLen int        // served prefix length, default 64

	// RouteTable != 0 enables routed-prefix mode (see internal/pdroute).
	RouteTable   int
	RulePriority int // default 5000

	// retransmission tuning, mainly for tests (zero = defaults)
	InitialTimeout time.Duration
	MaxTimeout     time.Duration
	Attempts       int
}

// DNSConfig enables the DNS forwarder on one served interface.
type DNSConfig struct {
	Port       int  // listen port, default 53
	Redirect53 bool // REDIRECT iface-ip:53 -> Port when Port != 53
	Upstream   string
	Upstreams  []string
}

// IfaceConfig is one served interface.
type IfaceConfig struct {
	Name string
	Tag  string // opaque, echoed in events/status (e.g. DroidVM vlan id)
	// Served VM-side prefixes (gateway address + length). These are the
	// authoritative source for the DHCP pools and the SLAAC/RA prefix — they
	// are NOT scraped off the interface's live addresses. Prefix6 is ignored
	// when PD is configured: there the delegation result drives v6.
	Prefix4 netip.Prefix
	Prefix6 netip.Prefix
	DHCP4   DHCP4Config
	DHCP6   DHCP6Config
	SLAAC   bool
	RA      RAConfig // Enabled/Managed/Autonomous derived; lifetimes honored
	PD      *PDConfig
	DNS     *DNSConfig
}

func (c *IfaceConfig) normalize() error {
	if c.Name == "" {
		return fmt.Errorf("interface needs a name")
	}
	if err := c.DHCP4.normalize(); err != nil {
		return fmt.Errorf("%s: %w", c.Name, err)
	}
	if err := c.DHCP6.normalize(); err != nil {
		return fmt.Errorf("%s: %w", c.Name, err)
	}
	c.RA.Enabled = c.SLAAC || c.DHCP6.Enabled
	c.RA.Autonomous = c.SLAAC
	c.RA.Managed = c.DHCP6.Enabled
	c.RA.Other = c.DHCP6.Enabled || c.DNS != nil
	c.RA.normalize()
	if c.PD != nil {
		if c.PD.Uplink == "" {
			return fmt.Errorf("%s: pd needs an uplink", c.Name)
		}
		if len(c.PD.DUID) < 2 {
			return fmt.Errorf("%s: pd needs a duid", c.Name)
		}
		if c.PD.PrefixLen <= 0 || c.PD.PrefixLen > 128 {
			c.PD.PrefixLen = 64
		}
		if !c.PD.Suffix.IsValid() {
			c.PD.Suffix = netip.MustParseAddr("::1")
		}
		if c.PD.RouteTable != 0 && c.PD.RulePriority == 0 {
			c.PD.RulePriority = 5000
		}
	}
	if c.DNS != nil && c.DNS.Port <= 0 {
		c.DNS.Port = 53
	}
	return nil
}

// env is the read-only world one protocol server sees: live addressing and
// the frame transmit path of its interface.
type env struct {
	name      string
	mac       func() net.HardwareAddr
	v4        func() (netip.Prefix, bool) // configured pool/gateway prefix
	v6        func() (netip.Prefix, bool) // pool/lease prefix (configured or PD)
	v6all     func() []netip.Prefix       // served v6 prefix(es) for RA
	linkLocal func() netip.Addr
	write     func([]byte) error
	done      <-chan struct{}
}

// Iface serves one interface: owns the packet socket, the protocol
// servers and the optional PD client / DNS forwarder.
type Iface struct {
	cfg     IfaceConfig
	watcher *ifwatch.Watcher
	store   *stateStore

	mu     sync.Mutex
	state  ifwatch.State
	conn   *transport.Conn
	pdAddr netip.Prefix // address this iface carries from PD (we added it)

	d4   *dhcp4Server
	d6   *dhcp6Server
	ra   *raServer
	pdc  *pd.Client
	pdr  *pdroute.Routes
	dns  *dnsfwd.Server
	dnat *dnsfwd.DNATRule

	done chan struct{}
	once sync.Once
}

func newIface(cfg IfaceConfig, watcher *ifwatch.Watcher, store *stateStore) *Iface {
	it := &Iface{
		cfg:     cfg,
		watcher: watcher,
		store:   store,
		done:    make(chan struct{}),
	}
	it.mu.Lock()
	it.state = ifwatch.Snapshot(cfg.Name)
	it.mu.Unlock()

	e := &env{
		name:      cfg.Name,
		mac:       it.envMAC,
		v4:        it.envV4,
		v6:        it.envV6,
		v6all:     it.envV6All,
		linkLocal: it.envLinkLocal,
		write:     it.envWrite,
		done:      it.done,
	}
	it.d4 = newDHCP4Server(e, cfg.DHCP4)
	it.d6 = newDHCP6Server(e, cfg.DHCP6)
	it.ra = newRAServer(e, cfg.RA)

	markDirty := store.markDirty
	it.d4.leases.changed = markDirty
	it.d6.leases.changed = markDirty

	if cfg.PD != nil {
		it.pdc = pd.New(pd.Config{
			Uplink:         cfg.PD.Uplink,
			DUID:           cfg.PD.DUID,
			IAID:           cfg.PD.IAID,
			InitialTimeout: cfg.PD.InitialTimeout,
			MaxTimeout:     cfg.PD.MaxTimeout,
			Attempts:       cfg.PD.Attempts,
		}, it.onPDChange)
		if cfg.PD.RouteTable != 0 {
			it.pdr = pdroute.New(pdroute.Config{
				Iface:        cfg.Name,
				Uplink:       cfg.PD.Uplink,
				Table:        cfg.PD.RouteTable,
				RulePriority: cfg.PD.RulePriority,
			})
		}
	}
	return it
}

func (it *Iface) start() {
	go it.runLoop()
	go it.watchLoop()
	// Sysctls and crash-leftover cleanup are process-lifetime; a state
	// restore may already have called Install (which starts lazily).
	if it.pdr != nil {
		it.pdr.Start()
	}
	if it.pdc != nil {
		it.pdc.Start()
	}
	if it.cfg.DNS != nil {
		go it.startDNS()
	}
}

func (it *Iface) stop() {
	it.once.Do(func() { close(it.done) })
	if it.pdc != nil {
		it.pdc.Stop()
	}
	it.mu.Lock()
	conn := it.conn
	it.conn = nil
	pdAddr := it.pdAddr
	it.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	if it.dns != nil {
		it.dns.Close()
	}
	if it.dnat != nil {
		it.dnat.Remove()
	}
	if pdAddr.IsValid() {
		it.removeAddr(pdAddr)
	}
	// After the IP state: stops being a router, then restores accept_ra.
	if it.pdr != nil {
		it.pdr.Stop()
	}
}

// --- env accessors ---

func (it *Iface) snapshot() ifwatch.State {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.state
}

func (it *Iface) envMAC() net.HardwareAddr {
	st := it.snapshot()
	if len(st.MAC) == 6 {
		return st.MAC
	}
	return net.HardwareAddr{0x02, 0, 0, 0, 0, 0}
}

// envV4 is the configured VM-side IPv4 prefix. The served prefix is
// authoritative config, never scraped off the interface's live addresses.
func (it *Iface) envV4() (netip.Prefix, bool) {
	if it.cfg.Prefix4.IsValid() {
		return it.cfg.Prefix4, true
	}
	return netip.Prefix{}, false
}

// envV6 picks the lease/pool prefix: the live PD delegation when PD is
// configured (invalid until one is held, dropped the moment it is lost),
// otherwise the configured static prefix. The interface's live addresses
// are never consulted.
func (it *Iface) envV6() (netip.Prefix, bool) {
	if it.cfg.PD != nil {
		it.mu.Lock()
		pdAddr := it.pdAddr
		it.mu.Unlock()
		if pdAddr.IsValid() {
			return pdAddr, true
		}
		return netip.Prefix{}, false
	}
	if it.cfg.Prefix6.IsValid() {
		return it.cfg.Prefix6, true
	}
	return netip.Prefix{}, false
}

// envV6All is the set of VM-side IPv6 prefixes RA advertises: the single
// configured-or-PD prefix. Returning nothing while a PD delegation is absent
// is what lets RA deprecate a prefix the moment PD loses it.
func (it *Iface) envV6All() []netip.Prefix {
	if p, ok := it.envV6(); ok {
		return []netip.Prefix{p}
	}
	return nil
}

func (it *Iface) envLinkLocal() netip.Addr {
	return it.snapshot().LinkLocal
}

func (it *Iface) envWrite(frame []byte) error {
	it.mu.Lock()
	conn := it.conn
	it.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("%s: not attached", it.cfg.Name)
	}
	return conn.Write(frame)
}

// --- main loops ---

// runLoop (re)attaches the packet socket whenever the interface exists,
// surviving interface deletion/recreation.
func (it *Iface) runLoop() {
	for {
		select {
		case <-it.done:
			return
		default:
		}
		st := ifwatch.Snapshot(it.cfg.Name)
		it.mu.Lock()
		it.state = st
		it.mu.Unlock()
		if !st.Exists {
			if !it.sleep(2 * time.Second) {
				return
			}
			continue
		}
		conn, err := transport.Open(it.cfg.Name)
		if err != nil {
			log.Printf("%s: attach: %v", it.cfg.Name, err)
			if !it.sleep(2 * time.Second) {
				return
			}
			continue
		}
		it.mu.Lock()
		it.conn = conn
		it.mu.Unlock()
		Emit("attached", map[string]any{"iface": it.cfg.Name, "tag": it.cfg.Tag})
		it.readLoop(conn)
		it.mu.Lock()
		if it.conn == conn {
			it.conn = nil
		}
		it.mu.Unlock()
		conn.Close()
	}
}

func (it *Iface) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-it.done:
		return false
	case <-t.C:
		return true
	}
}

func (it *Iface) readLoop(conn *transport.Conn) {
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		pkt, ok := packet.Parse(buf[:n])
		if !ok {
			continue
		}
		if it.d4.handleFrame(pkt) {
			continue
		}
		if it.d6.handleFrame(pkt) {
			continue
		}
		it.ra.handleFrame(pkt)
	}
}

// watchLoop refreshes addressing on netlink changes and nudges the
// components that depend on it.
func (it *Iface) watchLoop() {
	ch := it.watcher.Subscribe()
	for {
		select {
		case <-it.done:
			return
		case <-ch:
		}
		st := ifwatch.Snapshot(it.cfg.Name)
		it.mu.Lock()
		old := it.state
		it.state = st
		it.mu.Unlock()
		if !equalState(old, st) {
			it.ra.Kick()
		}
		// PD rides on uplink changes too: waking is cheap, and a confirmed
		// still-valid delegation is kept rather than re-solicited
		if it.pdc != nil {
			it.pdc.Wakeup()
		}
	}
}

func equalState(a, b ifwatch.State) bool {
	if a.Exists != b.Exists || a.Up != b.Up || a.Index != b.Index ||
		len(a.V4) != len(b.V4) || len(a.V6) != len(b.V6) || a.LinkLocal != b.LinkLocal {
		return false
	}
	for i := range a.V4 {
		if a.V4[i] != b.V4[i] {
			return false
		}
	}
	for i := range a.V6 {
		if a.V6[i] != b.V6[i] {
			return false
		}
	}
	return true
}

// --- PD plumbing ---

// composePD merges the delegated prefix with the configured suffix:
// address = (first PrefixLen-bits of the delegation) | suffix.
func (it *Iface) composePD(delegated netip.Prefix) netip.Prefix {
	plen := it.cfg.PD.PrefixLen
	base := delegated.Masked().Addr().As16()
	sfx := it.cfg.PD.Suffix.As16()
	var out [16]byte
	for i := range out {
		out[i] = base[i] | sfx[i]
	}
	return netip.PrefixFrom(netip.AddrFrom16(out), plen)
}

func (it *Iface) onPDChange(delegated netip.Prefix, ok bool) {
	if ok {
		addr := it.composePD(delegated)
		it.mu.Lock()
		it.pdAddr = addr
		it.mu.Unlock()
		it.addAddr(addr)
		fields := map[string]any{
			"iface": it.cfg.Name, "tag": it.cfg.Tag,
			"prefix": delegated.String(), "address": addr.String(),
		}
		if it.pdr != nil {
			it.pdr.Install(addr.Masked())
			fields["route_table"] = it.cfg.PD.RouteTable
		}
		Emit("pd_prefix", fields)
	} else {
		it.mu.Lock()
		addr := it.pdAddr
		it.pdAddr = netip.Prefix{}
		it.mu.Unlock()
		// Order: stop steering traffic at the dead prefix, then drop the
		// address. Nothing IP-derived may survive a released delegation.
		if it.pdr != nil {
			it.pdr.Clear()
		}
		if addr.IsValid() {
			it.removeAddr(addr)
		}
		Emit("pd_lost", map[string]any{
			"iface": it.cfg.Name, "tag": it.cfg.Tag, "prefix": delegated.String(),
		})
	}
	it.ra.Kick()
	it.store.markDirty()
}

func (it *Iface) addAddr(p netip.Prefix) {
	link, err := netlink.LinkByName(it.cfg.Name)
	if err != nil {
		log.Printf("%s: pd addr add: %v", it.cfg.Name, err)
		return
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{
		IP:   p.Addr().AsSlice(),
		Mask: net.CIDRMask(p.Bits(), 128),
	}}
	if err := netlink.AddrAdd(link, addr); err != nil && !isExist(err) {
		log.Printf("%s: pd addr add %s: %v", it.cfg.Name, p, err)
	}
}

func (it *Iface) removeAddr(p netip.Prefix) {
	link, err := netlink.LinkByName(it.cfg.Name)
	if err != nil {
		return
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{
		IP:   p.Addr().AsSlice(),
		Mask: net.CIDRMask(p.Bits(), 128),
	}}
	_ = netlink.AddrDel(link, addr)
}

func isExist(err error) bool {
	return err != nil && (err.Error() == "file exists" || err.Error() == "address already exists")
}

// --- DNS ---

func (it *Iface) startDNS() {
	cfg := it.cfg.DNS
	up := buildUpstream(cfg)
	for {
		srv, err := dnsfwd.New(it.cfg.Name, cfg.Port, up)
		if err != nil {
			log.Printf("%s: dns listen :%d: %v", it.cfg.Name, cfg.Port, err)
			if !it.sleep(5 * time.Second) {
				return
			}
			continue
		}
		it.mu.Lock()
		it.dns = srv
		it.mu.Unlock()
		Emit("dns_ready", map[string]any{
			"iface": it.cfg.Name, "tag": it.cfg.Tag, "port": srv.Port(),
		})
		break
	}
	if cfg.Redirect53 && cfg.Port != 53 {
		go it.maintainDNAT()
	}
	<-it.done
}

// maintainDNAT keeps the :53 REDIRECT in sync with the interface's
// (changing) IPv4 address.
func (it *Iface) maintainDNAT() {
	ch := it.watcher.Subscribe()
	var cur string
	apply := func() {
		v4, ok := it.envV4()
		ip := ""
		if ok {
			ip = v4.Addr().String()
		}
		if ip == cur {
			return
		}
		if it.dnat != nil {
			it.dnat.Remove()
			it.dnat = nil
		}
		cur = ip
		if ip == "" {
			return
		}
		rule, err := dnsfwd.InstallDNAT(it.cfg.Name, ip, it.cfg.DNS.Port)
		if err != nil {
			log.Printf("%s: dnat: %v", it.cfg.Name, err)
			return
		}
		it.dnat = rule
	}
	apply()
	for {
		select {
		case <-it.done:
			return
		case <-ch:
			apply()
		}
	}
}

func buildUpstream(cfg *DNSConfig) dnsfwd.Upstream {
	var ups []dnsfwd.Upstream
	mode := cfg.Upstream
	if mode == "" {
		mode = "auto"
	}
	if mode == "auto" || mode == "android" {
		if android := dnsfwd.NewAndroid(); android != nil {
			ups = append(ups, android)
		}
	}
	if len(cfg.Upstreams) > 0 {
		ups = append(ups, dnsfwd.NewStatic(cfg.Upstreams))
	}
	if mode != "android" {
		ups = append(ups, dnsfwd.NewResolvConf(""))
	}
	return dnsfwd.NewChain(ups...)
}

// --- persistence glue ---

func (it *Iface) persisted() *persistedIface {
	p := &persistedIface{
		Statics4: it.d4.ListStatic(),
		Statics6: it.d6.ListStatic(),
		Leases4:  it.d4.Leases(),
		Leases6:  it.d6.Leases(),
	}
	if it.pdc != nil {
		p.PD = it.pdc.Binding()
	}
	return p
}

func (it *Iface) restore(p *persistedIface) {
	if p == nil {
		return
	}
	if len(p.Statics4) > 0 {
		_ = it.d4.ReplaceStatics(p.Statics4)
	}
	if len(p.Statics6) > 0 {
		_ = it.d6.ReplaceStatics(p.Statics6)
	}
	it.d4.leases.load(p.Leases4)
	it.d6.leases.load(p.Leases6)
	if it.pdc != nil && p.PD != nil {
		it.pdc.Restore(*p.PD)
		// re-plumb the address so serving resumes before the first confirm
		if time.Now().Before(p.PD.ExpiresAt) {
			it.onPDChange(p.PD.Prefix, true)
		}
	}
}
