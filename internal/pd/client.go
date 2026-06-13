// Package pd implements a DHCPv6 prefix-delegation client (RFC 8415,
// IA_PD only): SOLICIT -> ADVERTISE -> REQUEST -> REPLY, then RENEW at T1 /
// REBIND at T2 and a full re-solicit when the delegation expires.
//
// Roaming behavior: while the held delegation is still valid, a wakeup
// (link change, daemon-detected reconnect) confirms it — unicast-style
// RENEW to the remembered server first, then a multicast REBIND any server
// can answer. A same-L2 roam (different SSID, same network) confirms and
// the prefix is kept without renumbering; a network without a PD server
// fails the confirmation and the prefix is withdrawn, which stops DHCPv6
// and SLAAC on the served interface.
package pd

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	serverPort = 547
	clientPort = 546
)

// Config is one PD client instance.
type Config struct {
	Uplink string // interface the DHCPv6 exchange runs on
	DUID   []byte // client DUID, stable across runs
	IAID   uint32

	// retransmission tuning (zero values mean RFC-ish defaults)
	InitialTimeout time.Duration
	MaxTimeout     time.Duration
	Attempts       int
}

func (c *Config) normalize() {
	if c.InitialTimeout <= 0 {
		c.InitialTimeout = time.Second
	}
	if c.MaxTimeout <= 0 {
		c.MaxTimeout = 32 * time.Second
	}
	if c.Attempts <= 0 {
		c.Attempts = 6
	}
}

// Binding is the live delegation.
type Binding struct {
	Prefix    netip.Prefix `json:"prefix"`
	BoundAt   time.Time    `json:"bound_at"`
	ExpiresAt time.Time    `json:"expires_at"`
}

// Callback reports delegation changes; ok=false means the prefix was lost.
type Callback func(prefix netip.Prefix, ok bool)

// Client runs the PD state machine on one uplink.
type Client struct {
	cfg      Config
	callback Callback

	mu         sync.Mutex
	state      string
	binding    *Binding
	serverDUID dhcpv6.DUID
	startedAt  time.Time

	wake chan struct{}
	done chan struct{}
	once sync.Once
}

// New creates a stopped client; Start launches it.
func New(cfg Config, cb Callback) *Client {
	cfg.normalize()
	return &Client{
		cfg:      cfg,
		callback: cb,
		state:    "stopped",
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
}

// Restore seeds a previously persisted binding so a daemon restart confirms
// it (RENEW/REBIND) instead of re-soliciting from scratch.
func (c *Client) Restore(b Binding) {
	if !b.Prefix.IsValid() || time.Now().After(b.ExpiresAt) {
		return
	}
	c.mu.Lock()
	c.binding = &b
	c.mu.Unlock()
}

func (c *Client) Start() { go c.run() }

func (c *Client) Stop() {
	c.once.Do(func() { close(c.done) })
}

// Wakeup retries now instead of waiting out the current sleep — used when
// the uplink's link state or addresses changed.
func (c *Client) Wakeup() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Binding returns the live delegation, or nil.
func (c *Client) Binding() *Binding {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.binding == nil {
		return nil
	}
	cp := *c.binding
	return &cp
}

// State returns the FSM state for status reporting.
func (c *Client) State() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *Client) setState(s string) {
	c.mu.Lock()
	c.state = s
	c.mu.Unlock()
}

func (c *Client) stopped() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// sleep waits d unless woken or stopped; returns false when stopped.
func (c *Client) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-c.done:
		return false
	case <-c.wake:
		return true
	case <-t.C:
		return true
	}
}

func (c *Client) dropPrefix() {
	c.mu.Lock()
	b := c.binding
	c.binding = nil
	c.serverDUID = nil
	c.mu.Unlock()
	if b != nil {
		log.Printf("pd[%s]: prefix %s lost", c.cfg.Uplink, b.Prefix)
		c.callback(b.Prefix, false)
	}
}

func (c *Client) run() {
	for !c.stopped() {
		c.setState("resolving")
		conn, err := c.openSocket()
		if err != nil {
			if !c.sleep(5 * time.Second) {
				break
			}
			continue
		}
		c.sessionLoop(conn)
		conn.Close()
		if !c.stopped() && !c.sleep(5*time.Second) {
			break
		}
	}
	c.setState("stopped")
}

// openSocket binds UDP :546 to the uplink's link-local address; the zone
// pins egress to that interface.
func (c *Client) openSocket() (*net.UDPConn, error) {
	ifi, err := net.InterfaceByName(c.cfg.Uplink)
	if err != nil {
		return nil, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}
	var ll net.IP
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.To4() == nil && ipnet.IP.IsLinkLocalUnicast() {
			ll = ipnet.IP
			break
		}
	}
	if ll == nil {
		return nil, fmt.Errorf("no link-local address on %s", c.cfg.Uplink)
	}
	return net.ListenUDP("udp6", &net.UDPAddr{IP: ll, Port: clientPort, Zone: c.cfg.Uplink})
}

func (c *Client) serverAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.ParseIP("ff02::1:2"),
		Port: serverPort,
		Zone: c.cfg.Uplink,
	}
}

// uplinkReady reports whether the uplink can carry DHCPv6 right now: it is
// up and has a non-tentative link-local address. Confirming a delegation
// while the link is down (mid-roam) would always fail and must not be
// mistaken for "this network has no PD server".
func (c *Client) uplinkReady() bool {
	link, err := netlink.LinkByName(c.cfg.Uplink)
	if err != nil {
		return false
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		return false
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if a.IP.IsLinkLocalUnicast() && a.Flags&unix.IFA_F_TENTATIVE == 0 {
			return true
		}
	}
	return false
}

func (c *Client) sessionLoop(conn *net.UDPConn) {
	for !c.stopped() {
		c.mu.Lock()
		binding := c.binding
		c.mu.Unlock()

		// Reconnect with a still-valid delegation: confirm it on this link
		// rather than re-acquire. A same-network server confirms and the
		// prefix is kept; a different network can't confirm and we fall
		// through to a fresh SOLICIT.
		if binding != nil && time.Now().Before(binding.ExpiresAt) {
			if !c.uplinkReady() {
				// mid-roam: keep the (still valid) prefix and wait for
				// the link to come back before judging it
				if !c.sleep(time.Second) {
					return
				}
				continue
			}
			if c.confirmExisting(conn) {
				if !c.boundLoop(conn) {
					return // socket error: reopen
				}
				continue
			}
			log.Printf("pd[%s]: prefix not confirmed, re-soliciting", c.cfg.Uplink)
			c.dropPrefix()
		}
		if !c.acquireFresh(conn) {
			if !c.sleep(5 * time.Second) {
				return
			}
			// the socket may refer to a replaced interface: reopen it
			return
		}
		if !c.boundLoop(conn) {
			return
		}
	}
}

// confirmExisting: unicast-style RENEW to the remembered server first (fast
// path when it's still there), then a multicast REBIND any server can
// answer. Returns true on confirmation.
func (c *Client) confirmExisting(conn *net.UDPConn) bool {
	c.mu.Lock()
	server := c.serverDUID
	c.mu.Unlock()
	if server != nil {
		c.setState("renewing")
		c.markStart()
		if reply := c.exchange(conn, dhcpv6.MessageTypeRenew, server, dhcpv6.MessageTypeReply); reply != nil && c.applyReply(reply) {
			return true
		}
	}
	c.setState("rebinding")
	c.markStart()
	if reply := c.exchange(conn, dhcpv6.MessageTypeRebind, nil, dhcpv6.MessageTypeReply); reply != nil && c.applyReply(reply) {
		return true
	}
	return false
}

// acquireFresh: SOLICIT -> ADVERTISE -> REQUEST -> REPLY.
func (c *Client) acquireFresh(conn *net.UDPConn) bool {
	c.setState("soliciting")
	c.markStart()
	adv := c.exchange(conn, dhcpv6.MessageTypeSolicit, nil, dhcpv6.MessageTypeAdvertise)
	if adv == nil {
		return false
	}
	advServer := adv.Options.ServerID()
	if advServer == nil {
		return false
	}
	c.setState("requesting")
	reply := c.exchange(conn, dhcpv6.MessageTypeRequest, advServer, dhcpv6.MessageTypeReply)
	if reply == nil || !c.applyReply(reply) {
		return false
	}
	return true
}

// boundLoop holds the lease: RENEW at T1, REBIND at T2, give up at expiry.
// Returns false on socket-level errors (caller reopens).
func (c *Client) boundLoop(conn *net.UDPConn) bool {
	for !c.stopped() {
		c.mu.Lock()
		b := c.binding
		server := c.serverDUID
		c.mu.Unlock()
		if b == nil {
			return true
		}
		c.setState("bound")

		now := time.Now()
		window := b.ExpiresAt.Sub(b.BoundAt)
		t1At := b.BoundAt.Add(window / 2)
		t2At := b.BoundAt.Add(window * 4 / 5)

		if now.Before(t1At) {
			d := time.Until(t1At)
			if d > time.Minute {
				d = time.Minute
			}
			if !c.sleep(d) {
				return true
			}
			// a wakeup within validity: re-confirm on the (possibly new)
			// link — but only once the uplink is actually usable, so a
			// down-phase mid-roam never counts as a failed confirmation
			c.mu.Lock()
			cur := c.binding
			c.mu.Unlock()
			if cur != nil && time.Now().Before(t1At) && c.uplinkReady() {
				if !c.confirmExisting(conn) {
					log.Printf("pd[%s]: prefix not confirmed after wakeup, re-soliciting", c.cfg.Uplink)
					c.dropPrefix()
					return true
				}
			}
			continue
		}
		if now.After(b.ExpiresAt) {
			log.Printf("pd[%s]: delegation expired", c.cfg.Uplink)
			c.dropPrefix()
			return true
		}

		typ := dhcpv6.MessageTypeRenew
		var dst dhcpv6.DUID = server
		if now.After(t2At) || server == nil {
			typ = dhcpv6.MessageTypeRebind
			dst = nil
		}
		c.setState(map[dhcpv6.MessageType]string{
			dhcpv6.MessageTypeRenew:  "renewing",
			dhcpv6.MessageTypeRebind: "rebinding",
		}[typ])
		c.markStart()
		reply := c.exchange(conn, typ, dst, dhcpv6.MessageTypeReply)
		if reply != nil && c.applyReply(reply) {
			continue
		}
		if time.Now().After(b.ExpiresAt) {
			c.dropPrefix()
			return true
		}
	}
	return true
}

func (c *Client) markStart() {
	c.mu.Lock()
	c.startedAt = time.Now()
	c.mu.Unlock()
}

// exchange sends one message and waits for the matching response, with
// exponential retransmission.
func (c *Client) exchange(conn *net.UDPConn, typ dhcpv6.MessageType, serverID dhcpv6.DUID, expect dhcpv6.MessageType) *dhcpv6.Message {
	var txn dhcpv6.TransactionID
	if _, err := rand.Read(txn[:]); err != nil {
		return nil
	}
	timeout := c.cfg.InitialTimeout
	for attempt := 0; attempt < c.cfg.Attempts && !c.stopped(); attempt++ {
		msg, err := c.buildMessage(typ, txn, serverID)
		if err != nil {
			return nil
		}
		if _, err := conn.WriteToUDP(msg.ToBytes(), c.serverAddr()); err != nil {
			return nil
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(deadline)
			buf := make([]byte, 1500)
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				break // timeout
			}
			parsed, err := dhcpv6.FromBytes(buf[:n])
			if err != nil {
				continue
			}
			resp, ok := parsed.(*dhcpv6.Message)
			if !ok || resp.MessageType != expect || resp.TransactionID != txn {
				continue
			}
			return resp
		}
		timeout *= 2
		if timeout > c.cfg.MaxTimeout {
			timeout = c.cfg.MaxTimeout
		}
	}
	return nil
}

func (c *Client) buildMessage(typ dhcpv6.MessageType, txn dhcpv6.TransactionID, serverID dhcpv6.DUID) (*dhcpv6.Message, error) {
	duid, err := dhcpv6.DUIDFromBytes(c.cfg.DUID)
	if err != nil {
		return nil, err
	}
	msg := &dhcpv6.Message{MessageType: typ, TransactionID: txn}
	msg.AddOption(dhcpv6.OptClientID(duid))
	if serverID != nil {
		msg.AddOption(dhcpv6.OptServerID(serverID))
	}
	c.mu.Lock()
	elapsed := time.Since(c.startedAt)
	binding := c.binding
	c.mu.Unlock()
	msg.AddOption(dhcpv6.OptElapsedTime(elapsed))
	msg.AddOption(dhcpv6.OptRequestedOption(dhcpv6.OptionIAPD))

	iapd := &dhcpv6.OptIAPD{IaId: iaidBytes(c.cfg.IAID)}
	if binding != nil {
		// include the held prefix as a hint / the binding being renewed
		ipnet := &net.IPNet{
			IP:   binding.Prefix.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(binding.Prefix.Bits(), 128),
		}
		iapd.Options.Add(&dhcpv6.OptIAPrefix{Prefix: ipnet})
	}
	msg.AddOption(iapd)
	return msg, nil
}

func iaidBytes(v uint32) [4]byte {
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// applyReply applies a REPLY's IA_PD; returns false when it carries no
// usable prefix.
func (c *Client) applyReply(reply *dhcpv6.Message) bool {
	iapd := reply.Options.OneIAPD()
	if iapd == nil {
		return false
	}
	if st := iapd.Options.Status(); st != nil && st.StatusCode != 0 {
		log.Printf("pd[%s]: IA_PD status %d (%s)", c.cfg.Uplink, st.StatusCode, st.StatusMessage)
		return false
	}
	var best *dhcpv6.OptIAPrefix
	for _, p := range iapd.Options.Prefixes() {
		if p.ValidLifetime <= 0 || p.Prefix == nil {
			continue
		}
		if best == nil || prefixLen(p) < prefixLen(best) {
			best = p
		}
	}
	if best == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(best.Prefix.IP.To16())
	if !ok {
		return false
	}
	ones, _ := best.Prefix.Mask.Size()
	prefix := netip.PrefixFrom(addr, ones).Masked()

	now := time.Now()
	b := Binding{Prefix: prefix, BoundAt: now, ExpiresAt: now.Add(best.ValidLifetime)}
	c.mu.Lock()
	old := c.binding
	c.binding = &b
	c.serverDUID = reply.Options.ServerID()
	c.mu.Unlock()

	if old == nil || old.Prefix != prefix {
		log.Printf("pd[%s]: delegation %s (valid %s)", c.cfg.Uplink, prefix, best.ValidLifetime)
		if old != nil && old.Prefix != prefix {
			c.callback(old.Prefix, false)
		}
		c.callback(prefix, true)
	}
	return true
}

func prefixLen(p *dhcpv6.OptIAPrefix) int {
	if p.Prefix == nil {
		return 129
	}
	ones, _ := p.Prefix.Mask.Size()
	return ones
}
