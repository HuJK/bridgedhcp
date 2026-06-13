package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/HuJK/bridgedhcp/internal/packet"
)

const (
	dhcp4ServerPort = 67
	dhcp4ClientPort = 68

	defaultLeaseTime = time.Hour
	leaseSweepEvery  = 30 * time.Second
)

var (
	broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	broadcastIP4 = net.IPv4bcast
)

// DHCP4Config configures the DHCPv4 server of one interface. The pool is
// expressed as offsets against the interface's live IPv4 prefix.
type DHCP4Config struct {
	Enabled         bool
	PoolOffsetStart uint64
	PoolOffsetEnd   uint64
	LeaseTime       time.Duration
	DNS             []netip.Addr // empty: the interface address
}

func (c *DHCP4Config) normalize() error {
	if !c.Enabled {
		return nil
	}
	if c.PoolOffsetStart == 0 || c.PoolOffsetEnd < c.PoolOffsetStart {
		return fmt.Errorf("dhcp4 pool offsets invalid: [%d, %d]", c.PoolOffsetStart, c.PoolOffsetEnd)
	}
	if c.LeaseTime <= 0 {
		c.LeaseTime = defaultLeaseTime
	}
	return nil
}

// dhcp4Server answers DHCPv4 at L2 on one interface. All addressing is
// derived from the interface's live prefix, so renumbering only requires
// the env to report the new prefix.
type dhcp4Server struct {
	env *env

	mu      sync.Mutex
	cfg     DHCP4Config
	statics map[string]*StaticBinding

	leases *leaseTable
}

func newDHCP4Server(e *env, cfg DHCP4Config) *dhcp4Server {
	s := &dhcp4Server{
		env:     e,
		cfg:     cfg,
		statics: make(map[string]*StaticBinding),
		leases:  newLeaseTable(),
	}
	go s.sweepLoop()
	return s
}

func (s *dhcp4Server) sweepLoop() {
	t := time.NewTicker(leaseSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-s.env.done:
			return
		case <-t.C:
			s.leases.expireSweep()
		}
	}
}

func (s *dhcp4Server) config() DHCP4Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Statics CRUD (API-driven).

func (s *dhcp4Server) PutStatic(b StaticBinding) error {
	if b.ID == "" {
		return fmt.Errorf("static binding needs an id")
	}
	if err := b.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.statics[b.ID] = &b
	s.mu.Unlock()
	return nil
}

func (s *dhcp4Server) ReplaceStatics(bs []StaticBinding) error {
	m, err := buildStaticSet(bs)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.statics = m
	s.mu.Unlock()
	return nil
}

func (s *dhcp4Server) ListStatic() []StaticBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StaticBinding, 0, len(s.statics))
	for _, b := range s.statics {
		out = append(out, *b)
	}
	return out
}

func (s *dhcp4Server) DeleteStatic(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.statics[id]; !ok {
		return fmt.Errorf("static binding %q not found", id)
	}
	delete(s.statics, id)
	return nil
}

func (s *dhcp4Server) Leases() []Lease { return s.leases.snapshot() }

func (s *dhcp4Server) ReleaseLease(ip netip.Addr) error {
	if !s.leases.release(ip) {
		return fmt.Errorf("lease %s not found", ip)
	}
	return nil
}

// handleFrame consumes UDP :67 packets. Returns true when the frame was a
// DHCPv4 packet (regardless of whether it was answered).
func (s *dhcp4Server) handleFrame(pkt packet.Ingress) bool {
	if !pkt.IsUDP4 || pkt.DstPort != dhcp4ServerPort {
		return false
	}
	cfg := s.config()
	prefix, ok := s.env.v4()
	if !cfg.Enabled || !ok {
		return true
	}

	req, err := dhcpv4.FromBytes(pkt.Payload)
	if err != nil || req.OpCode != dhcpv4.OpcodeBootRequest {
		return true
	}

	switch req.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		s.replyToDiscover(cfg, prefix, req)
	case dhcpv4.MessageTypeRequest:
		s.replyToRequest(cfg, prefix, req)
	case dhcpv4.MessageTypeRelease:
		if ip, ok := netip.AddrFromSlice(req.ClientIPAddr.To4()); ok && ip.IsValid() {
			s.leases.release(ip)
		}
	case dhcpv4.MessageTypeDecline:
		if rip := req.RequestedIPAddress(); rip != nil {
			if ip, ok := netip.AddrFromSlice(rip.To4()); ok && ip.IsValid() {
				// Mark declined addresses unusable for a while by leasing
				// them to a placeholder.
				s.leases.set(Lease{IP: ip, MAC: "declined", Expiry: time.Now().Add(cfg.LeaseTime)})
			}
		}
	}
	return true
}

func clientIDOf(req *dhcpv4.DHCPv4) string {
	return hex.EncodeToString(req.Options.Get(dhcpv4.OptionClientIdentifier))
}

// selectIP picks (and books) the address for a client following static
// bindings, the existing lease, then the pool. Returns the invalid Addr if
// nothing can be offered.
func (s *dhcp4Server) selectIP(cfg DHCP4Config, prefix netip.Prefix, req *dhcpv4.DHCPv4) netip.Addr {
	mac := req.ClientHWAddr.String()
	cid := clientIDOf(req)
	gwIP := prefix.Addr()
	poolStart := addrAtOffset(prefix, cfg.PoolOffsetStart)
	poolEnd := addrAtOffset(prefix, cfg.PoolOffsetEnd)

	s.mu.Lock()
	bindings := make([]*StaticBinding, 0, len(s.statics))
	for _, b := range s.statics {
		bindings = append(bindings, b)
	}
	s.mu.Unlock()

	staticIPs := make(map[netip.Addr]bool, len(bindings))
	for _, b := range bindings {
		if ip := addrAtOffset(prefix, b.Offset); ip.IsValid() {
			staticIPs[ip] = true
		}
	}

	lease := Lease{
		MAC:      mac,
		ClientID: cid,
		Hostname: req.HostName(),
		Expiry:   time.Now().Add(cfg.LeaseTime),
	}

	if b := matchBinding(bindings, mac, cid); b != nil {
		ip := addrAtOffset(prefix, b.Offset)
		if ip.IsValid() {
			if s.leases.inUse(ip, mac, cid) {
				return netip.Addr{}
			}
			lease.IP = ip
			lease.Static = true
			s.leases.set(lease)
			return ip
		}
	}

	if cur := s.leases.byClient(mac, cid); cur != nil && !staticIPs[cur.IP] && prefix.Masked().Contains(cur.IP) {
		lease.IP = cur.IP
		s.leases.set(lease)
		return cur.IP
	}

	if !poolStart.IsValid() || !poolEnd.IsValid() {
		return netip.Addr{}
	}

	// Honor a requested address when it is free and inside the pool.
	if reqIP := req.RequestedIPAddress(); reqIP != nil {
		if rip, ok := netip.AddrFromSlice(reqIP.To4()); ok && rip.IsValid() {
			if !poolEnd.Less(rip) && !rip.Less(poolStart) && rip != gwIP && !staticIPs[rip] && !s.leases.inUse(rip, mac, cid) {
				lease.IP = rip
				s.leases.set(lease)
				return rip
			}
		}
	}

	return s.leases.allocate(poolStart, poolEnd, func(ip netip.Addr) bool {
		return ip == gwIP || staticIPs[ip]
	}, lease)
}

func (s *dhcp4Server) replyToDiscover(cfg DHCP4Config, prefix netip.Prefix, req *dhcpv4.DHCPv4) {
	ip := s.selectIP(cfg, prefix, req)
	if !ip.IsValid() {
		return // pool exhausted: stay silent
	}
	s.sendReply(cfg, prefix, req, dhcpv4.MessageTypeOffer, ip)
}

func (s *dhcp4Server) replyToRequest(cfg DHCP4Config, prefix netip.Prefix, req *dhcpv4.DHCPv4) {
	// The address the client asks for: option 50 (SELECTING/INIT-REBOOT)
	// or ciaddr (RENEWING/REBINDING).
	var want netip.Addr
	if rip := req.RequestedIPAddress(); rip != nil {
		want, _ = netip.AddrFromSlice(rip.To4())
	}
	if !want.IsValid() || want.IsUnspecified() {
		var ok bool
		want, ok = netip.AddrFromSlice(req.ClientIPAddr.To4())
		if !ok || !want.IsValid() || want.IsUnspecified() {
			s.sendNak(prefix, req)
			return
		}
	}
	got := s.selectIP(cfg, prefix, req)
	if !got.IsValid() || got != want {
		s.sendNak(prefix, req)
		return
	}
	s.sendReply(cfg, prefix, req, dhcpv4.MessageTypeAck, got)
}

func (s *dhcp4Server) dnsServers(cfg DHCP4Config, prefix netip.Prefix) []net.IP {
	if len(cfg.DNS) == 0 {
		return []net.IP{prefix.Addr().AsSlice()}
	}
	out := make([]net.IP, 0, len(cfg.DNS))
	for _, a := range cfg.DNS {
		out = append(out, a.AsSlice())
	}
	return out
}

func (s *dhcp4Server) sendReply(cfg DHCP4Config, prefix netip.Prefix, req *dhcpv4.DHCPv4, typ dhcpv4.MessageType, ip netip.Addr) {
	gw := net.IP(prefix.Addr().AsSlice())
	mask := net.CIDRMask(prefix.Bits(), 32)

	reply, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(typ),
		dhcpv4.WithServerIP(gw),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(gw)),
		dhcpv4.WithOption(dhcpv4.OptSubnetMask(mask)),
		dhcpv4.WithOption(dhcpv4.OptRouter(gw)),
		dhcpv4.WithOption(dhcpv4.OptDNS(s.dnsServers(cfg, prefix)...)),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(cfg.LeaseTime)),
		dhcpv4.WithOption(dhcpv4.OptRenewTimeValue(cfg.LeaseTime/2)),
		dhcpv4.WithOption(dhcpv4.OptRebindingTimeValue(cfg.LeaseTime*7/8)),
	)
	if err != nil {
		return
	}
	reply.YourIPAddr = ip.AsSlice()
	s.transmit(prefix, req, reply, ip)
}

func (s *dhcp4Server) sendNak(prefix netip.Prefix, req *dhcpv4.DHCPv4) {
	gw := net.IP(prefix.Addr().AsSlice())
	reply, err := dhcpv4.NewReplyFromRequest(req,
		dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(gw)),
	)
	if err != nil {
		return
	}
	s.transmit(prefix, req, reply, netip.Addr{})
}

// transmit crafts the reply frame per RFC 2131 §4.1 addressing rules.
func (s *dhcp4Server) transmit(prefix netip.Prefix, req, reply *dhcpv4.DHCPv4, yiaddr netip.Addr) {
	dstMAC := net.HardwareAddr(req.ClientHWAddr)
	dstIP := broadcastIP4

	switch {
	case req.ClientIPAddr != nil && !req.ClientIPAddr.IsUnspecified():
		dstIP = req.ClientIPAddr
	case reply.MessageType() == dhcpv4.MessageTypeNak || req.IsBroadcast() || !yiaddr.IsValid():
		dstMAC = broadcastMAC
	default:
		dstIP = yiaddr.AsSlice()
	}

	frame := packet.CraftUDP4(s.env.mac(), dstMAC, prefix.Addr().AsSlice(), dstIP,
		dhcp4ServerPort, dhcp4ClientPort, reply.ToBytes())
	_ = s.env.write(frame)
}
