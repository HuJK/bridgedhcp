// Package ifwatch tracks link and address state of served interfaces via
// netlink subscription. Servers use the snapshot for link properties (MAC,
// link-local, up/exists) and to learn when those change. Served prefixes
// (DHCP pools, SLAAC/RA) are NOT taken from here: they come from static
// config or the PD delegation result (see server.IfaceConfig).
package ifwatch

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

// State is one interface's current addressing.
type State struct {
	Exists    bool
	Up        bool
	Index     int
	MAC       net.HardwareAddr
	V4        []netip.Prefix // global IPv4 addresses (address + prefix len)
	V6        []netip.Prefix // global IPv6 addresses
	LinkLocal netip.Addr     // IPv6 link-local address
}

// Snapshot reads the named interface's state directly from netlink.
func Snapshot(name string) State {
	var st State
	link, err := netlink.LinkByName(name)
	if err != nil {
		return st
	}
	attrs := link.Attrs()
	st.Exists = true
	st.Up = attrs.Flags&net.FlagUp != 0
	st.Index = attrs.Index
	st.MAC = attrs.HardwareAddr

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return st
	}
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		ones, _ := a.Mask.Size()
		switch {
		case ip.Is4():
			st.V4 = append(st.V4, netip.PrefixFrom(ip, ones))
		case ip.IsLinkLocalUnicast():
			st.LinkLocal = ip
		case ip.Is6():
			st.V6 = append(st.V6, netip.PrefixFrom(ip, ones))
		}
	}
	return st
}

// Watcher fans netlink change events out to subscribers, debounced.
type Watcher struct {
	mu   sync.Mutex
	subs []chan struct{}
	done chan struct{}
}

// NewWatcher starts the netlink subscriptions.
func NewWatcher() (*Watcher, error) {
	w := &Watcher{done: make(chan struct{})}
	addrCh := make(chan netlink.AddrUpdate, 64)
	linkCh := make(chan netlink.LinkUpdate, 64)
	if err := netlink.AddrSubscribe(addrCh, w.done); err != nil {
		return nil, err
	}
	if err := netlink.LinkSubscribe(linkCh, w.done); err != nil {
		close(w.done)
		return nil, err
	}
	go w.loop(addrCh, linkCh)
	return w, nil
}

// Subscribe returns a channel that receives a tick after any link or
// address change (coalesced). The channel has capacity 1; missed ticks
// merge.
func (w *Watcher) Subscribe() <-chan struct{} {
	ch := make(chan struct{}, 1)
	w.mu.Lock()
	w.subs = append(w.subs, ch)
	w.mu.Unlock()
	return ch
}

func (w *Watcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	select {
	case <-w.done:
	default:
		close(w.done)
	}
}

func (w *Watcher) loop(addrCh chan netlink.AddrUpdate, linkCh chan netlink.LinkUpdate) {
	var pending bool
	var timer *time.Timer
	var timerC <-chan time.Time
	arm := func() {
		if pending {
			return
		}
		pending = true
		timer = time.NewTimer(100 * time.Millisecond) // coalesce bursts
		timerC = timer.C
	}
	for {
		select {
		case <-w.done:
			return
		case _, ok := <-addrCh:
			if !ok {
				return
			}
			arm()
		case _, ok := <-linkCh:
			if !ok {
				return
			}
			arm()
		case <-timerC:
			pending = false
			timerC = nil
			w.mu.Lock()
			for _, ch := range w.subs {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
			w.mu.Unlock()
		}
	}
}
