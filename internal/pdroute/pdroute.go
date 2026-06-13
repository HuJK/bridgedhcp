// Package pdroute turns a served bridge into a routed IPv6 segment for
// its delegated prefix: guests use their own PD-derived source addresses
// end to end, independent of whether the host itself has any SLAAC
// address on the uplink (Android never runs DHCPv6, so on an RA-A=0
// network the host has none — host-socket NAT would be dead there).
//
// Mechanism: a dedicated routing table holds the on-link subnet route and
// a default route mirrored from the uplink's RA-learned router; a
// from/to rule pair on the prefix selects the table. Android's own rule
// stack only routes locally-originated traffic (its rules are gated on
// iif lo), so forwarded guest traffic needs both directions: "from
// <prefix>" for egress and "to <prefix>" for the replies.
//
// Two lifecycles, strictly separated:
//   - process lifetime: sysctls (uplink accept_ra 1->2, per-interface
//     forwarding), acquired on Start and restored on Stop; refcounted per
//     path so bridges sharing an uplink don't fight.
//   - prefix lifetime: everything that encodes the delegated prefix —
//     rules, routes, the table content — installed on Install and wiped
//     on Clear. After a pd_lost nothing on the system shows the prefix
//     ever existed.
//
// The table id is the crash-recovery key: Start wipes any rule or route
// still pointing at the table, so recovery after a crash and a normal
// start are the same code path. DroidVM must therefore assign each bridge
// a stable table id across restarts.
package pdroute

import (
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// routeProto marks routes we own (cosmetic: identification is by table).
const routeProto = 213

// mirrorResync is the fallback poll interval for the RA-default mirror;
// the netlink route subscription is the fast path.
const mirrorResync = 60 * time.Second

// Config describes one routed segment.
type Config struct {
	Iface        string // served (bridge) interface
	Uplink       string // PD uplink; RA default routes are mirrored from it
	Table        int    // dedicated routing table (also the cleanup key)
	RulePriority int    // priority of the from/to rule pair
}

// Routes owns the policy-routing state of one served interface.
type Routes struct {
	cfg Config

	mu      sync.Mutex
	started bool
	stopped bool
	prefix  netip.Prefix // installed prefix; invalid = nothing installed
	stop    chan struct{}
}

// New builds an inactive Routes; Start or the first Install activates it.
func New(cfg Config) *Routes {
	return &Routes{cfg: cfg, stop: make(chan struct{})}
}

// Start acquires the sysctls and wipes crash leftovers. Idempotent; also
// called implicitly by Install (state restore runs before Start).
func (r *Routes) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureStartedLocked()
}

func (r *Routes) ensureStartedLocked() {
	if r.started || r.stopped {
		return
	}
	r.started = true

	// Crash leftovers: any rule or route still on our table, regardless
	// of which (old, unknown) prefix it encodes.
	r.wipeRulesLocked(netip.Prefix{})
	r.flushTableLocked()

	// Order matters: accept_ra must be relaxed *before* the uplink starts
	// forwarding, or there is a window where the kernel drops RAs and the
	// host loses its own default route.
	sysctls.acquireAcceptRA(r.cfg.Uplink)
	sysctls.acquireForwarding(r.cfg.Uplink)
	sysctls.acquireForwarding(r.cfg.Iface)

	go r.mirrorLoop()
}

// Install plumbs the routing state for a (new) delegated prefix. On
// renumbering the new rules are added before stale ones are removed, so
// there is no window without policy routing.
func (r *Routes) Install(prefix netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	r.ensureStartedLocked()
	r.prefix = prefix

	link, err := netlink.LinkByName(r.cfg.Iface)
	if err != nil {
		log.Printf("pdroute %s: link: %v", r.cfg.Iface, err)
		return
	}

	// On-link subnet: the served prefix lives behind the bridge.
	subnet := &netlink.Route{
		Dst:       prefixToIPNet(prefix),
		LinkIndex: link.Attrs().Index,
		Table:     r.cfg.Table,
		Protocol:  routeProto,
	}
	if err := netlink.RouteReplace(subnet); err != nil {
		log.Printf("pdroute %s: subnet route %s: %v", r.cfg.Iface, prefix, err)
	}

	for _, dir := range []string{"from", "to"} {
		if err := r.addRule(dir, prefix); err != nil {
			log.Printf("pdroute %s: rule %s %s: %v", r.cfg.Iface, dir, prefix, err)
		}
	}
	// Drop rules for any previous prefix (renumbering) now that the new
	// pair is live.
	r.wipeRulesLocked(prefix)
	// Old subnet routes too; the mirror re-seeds the default right after.
	r.flushTableExceptLocked(prefix)

	r.syncDefaultLocked()
}

// Clear removes every trace of the prefix: the rule pair and the whole
// table content. Called on pd_lost; the sysctls stay (process lifetime).
func (r *Routes) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearLocked()
}

func (r *Routes) clearLocked() {
	if !r.prefix.IsValid() && !r.started {
		return
	}
	r.prefix = netip.Prefix{}
	r.wipeRulesLocked(netip.Prefix{})
	r.flushTableLocked()
}

// Stop clears the prefix state and restores the sysctls (reverse order:
// stop being a router before restoring accept_ra).
func (r *Routes) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	r.stopped = true
	close(r.stop)
	r.clearLocked()
	if r.started {
		sysctls.releaseForwarding(r.cfg.Iface)
		sysctls.releaseForwarding(r.cfg.Uplink)
		sysctls.releaseAcceptRA(r.cfg.Uplink)
	}
}

// --- rules ---

func (r *Routes) addRule(dir string, prefix netip.Prefix) error {
	rule := netlink.NewRule()
	rule.Family = netlink.FAMILY_V6
	rule.Table = r.cfg.Table
	rule.Priority = r.cfg.RulePriority
	if dir == "from" {
		rule.Src = prefixToIPNet(prefix)
	} else {
		rule.Dst = prefixToIPNet(prefix)
	}
	err := netlink.RuleAdd(rule)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

// wipeRulesLocked deletes every rule pointing at our table, except the
// from/to pair of `keep` (pass the zero Prefix to delete them all). The
// table is the only ownership marker that survives a crash.
func (r *Routes) wipeRulesLocked(keep netip.Prefix) {
	rules, err := netlink.RuleList(netlink.FAMILY_V6)
	if err != nil {
		log.Printf("pdroute %s: rule list: %v", r.cfg.Iface, err)
		return
	}
	var keepNet *net.IPNet
	if keep.IsValid() {
		keepNet = prefixToIPNet(keep)
	}
	for i := range rules {
		ru := rules[i]
		if ru.Table != r.cfg.Table {
			continue
		}
		if keepNet != nil && (ipNetEqual(ru.Src, keepNet) || ipNetEqual(ru.Dst, keepNet)) {
			continue
		}
		ru.Family = netlink.FAMILY_V6
		if err := netlink.RuleDel(&ru); err != nil {
			log.Printf("pdroute %s: rule del (table %d): %v", r.cfg.Iface, r.cfg.Table, err)
		}
	}
}

// --- table ---

func (r *Routes) listTable() []netlink.Route {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: r.cfg.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		log.Printf("pdroute %s: route list table %d: %v", r.cfg.Iface, r.cfg.Table, err)
		return nil
	}
	return routes
}

func (r *Routes) flushTableLocked() {
	r.flushTableExceptLocked(netip.Prefix{})
}

// flushTableExceptLocked empties our table, keeping only the subnet route
// of `keep` (zero Prefix keeps nothing). The mirrored default is always
// dropped; the mirror re-installs it while a prefix is active.
func (r *Routes) flushTableExceptLocked(keep netip.Prefix) {
	var keepNet *net.IPNet
	if keep.IsValid() {
		keepNet = prefixToIPNet(keep)
	}
	for _, rt := range r.listTable() {
		if keepNet != nil && rt.Gw == nil && ipNetEqual(rt.Dst, keepNet) {
			continue
		}
		rt := rt
		if err := netlink.RouteDel(&rt); err != nil {
			log.Printf("pdroute %s: route del table %d: %v", r.cfg.Iface, r.cfg.Table, err)
		}
	}
}

// --- RA default mirror ---

// mirrorLoop keeps our table's default route in sync with the uplink's
// RA-learned router. The kernel ages RA routes by itself; we mirror the
// live ones and follow deletions, so expiry needs no timers of our own.
func (r *Routes) mirrorLoop() {
	ch := make(chan netlink.RouteUpdate, 64)
	if err := netlink.RouteSubscribe(ch, r.stop); err != nil {
		log.Printf("pdroute %s: route subscribe: %v (falling back to polling)", r.cfg.Iface, err)
		ch = nil
	}
	tick := time.NewTicker(mirrorResync)
	defer tick.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-tick.C:
		case _, ok := <-ch:
			if !ok {
				ch = nil // subscription died; the ticker still covers us
				continue
			}
			// Coalesce bursts before resyncing.
		drain:
			for {
				select {
				case _, ok := <-ch:
					if !ok {
						ch = nil
						break drain
					}
				default:
					break drain
				}
			}
		}
		r.mu.Lock()
		if r.prefix.IsValid() {
			r.syncDefaultLocked()
		}
		r.mu.Unlock()
	}
}

// syncDefaultLocked mirrors the best uplink default route into our table,
// or removes ours when the uplink has none.
func (r *Routes) syncDefaultLocked() {
	if !r.prefix.IsValid() {
		return
	}
	link, err := netlink.LinkByName(r.cfg.Uplink)
	if err != nil {
		r.removeDefaultLocked()
		return
	}
	uplinkIdx := link.Attrs().Index

	// Dump all tables: mainline puts RA routes in main, Android in
	// per-interface tables (accept_ra_rt_table) and netd's per-network
	// tables. Table 0 = RT_TABLE_UNSPEC = no table filter.
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6,
		&netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		log.Printf("pdroute %s: route dump: %v", r.cfg.Iface, err)
		return
	}
	var best *netlink.Route
	for i := range routes {
		rt := &routes[i]
		if rt.Table == r.cfg.Table || rt.Protocol == routeProto {
			continue // ours (or another bridge's mirror)
		}
		if rt.LinkIndex != uplinkIdx || rt.Gw == nil || !isDefault(rt.Dst) {
			continue
		}
		if best == nil || betterDefault(rt, best) {
			best = rt
		}
	}
	if best == nil {
		r.removeDefaultLocked()
		return
	}
	def := &netlink.Route{
		Dst:       defaultDst(),
		Gw:        best.Gw,
		LinkIndex: uplinkIdx,
		Table:     r.cfg.Table,
		Protocol:  routeProto,
		Priority:  1024,
	}
	if err := netlink.RouteReplace(def); err != nil {
		log.Printf("pdroute %s: default via %s: %v", r.cfg.Iface, best.Gw, err)
	}
}

// betterDefault prefers RA-originated routes, then lower metric.
func betterDefault(a, b *netlink.Route) bool {
	aRA, bRA := a.Protocol == unix.RTPROT_RA, b.Protocol == unix.RTPROT_RA
	if aRA != bRA {
		return aRA
	}
	return a.Priority < b.Priority
}

func (r *Routes) removeDefaultLocked() {
	for _, rt := range r.listTable() {
		if rt.Gw == nil || !isDefault(rt.Dst) {
			continue
		}
		rt := rt
		if err := netlink.RouteDel(&rt); err != nil {
			log.Printf("pdroute %s: default del: %v", r.cfg.Iface, err)
		}
	}
}

// --- helpers ---

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   p.Masked().Addr().AsSlice(),
		Mask: net.CIDRMask(p.Bits(), 128),
	}
}

func defaultDst() *net.IPNet {
	return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
}

func isDefault(d *net.IPNet) bool {
	if d == nil {
		return true
	}
	ones, _ := d.Mask.Size()
	return ones == 0
}

func ipNetEqual(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == b
	}
	aOnes, aBits := a.Mask.Size()
	bOnes, bBits := b.Mask.Size()
	return aOnes == bOnes && aBits == bBits && a.IP.Equal(b.IP)
}
