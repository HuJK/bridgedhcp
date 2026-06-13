package server

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"

	"github.com/HuJK/bridgedhcp/internal/packet"
)

const (
	dhcp6ServerPort = 547
	dhcp6ClientPort = 546
)

// DHCP6Config configures the stateful DHCPv6 (IA_NA) server of one
// interface. The pool is expressed as offsets against the live IPv6 prefix,
// which may come from static configuration or a PD delegation.
type DHCP6Config struct {
	Enabled         bool
	PoolOffsetStart uint64
	PoolOffsetEnd   uint64
	LeaseTime       time.Duration
	DNS             []netip.Addr // empty: the interface address
}

func (c *DHCP6Config) normalize() error {
	if !c.Enabled {
		return nil
	}
	if c.PoolOffsetStart == 0 || c.PoolOffsetEnd < c.PoolOffsetStart {
		return fmt.Errorf("dhcp6 pool offsets invalid: [%d, %d]", c.PoolOffsetStart, c.PoolOffsetEnd)
	}
	if c.LeaseTime <= 0 {
		c.LeaseTime = defaultLeaseTime
	}
	return nil
}

// dhcp6Server implements a minimal stateful DHCPv6 server (IA_NA only) at
// L2. The client is identified by its DUID; static bindings share the
// offset machinery with DHCPv4.
type dhcp6Server struct {
	env *env

	mu      sync.Mutex
	cfg     DHCP6Config
	statics map[string]*StaticBinding

	leases *leaseTable
}

func newDHCP6Server(e *env, cfg DHCP6Config) *dhcp6Server {
	s := &dhcp6Server{
		env:     e,
		cfg:     cfg,
		statics: make(map[string]*StaticBinding),
		leases:  newLeaseTable(),
	}
	go s.sweepLoop()
	return s
}

func (s *dhcp6Server) sweepLoop() {
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

func (s *dhcp6Server) config() DHCP6Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *dhcp6Server) PutStatic(b StaticBinding) error {
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

func (s *dhcp6Server) ReplaceStatics(bs []StaticBinding) error {
	m, err := buildStaticSet(bs)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.statics = m
	s.mu.Unlock()
	return nil
}

func (s *dhcp6Server) ListStatic() []StaticBinding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StaticBinding, 0, len(s.statics))
	for _, b := range s.statics {
		out = append(out, *b)
	}
	return out
}

func (s *dhcp6Server) DeleteStatic(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.statics[id]; !ok {
		return fmt.Errorf("static binding %q not found", id)
	}
	delete(s.statics, id)
	return nil
}

func (s *dhcp6Server) Leases() []Lease { return s.leases.snapshot() }

func (s *dhcp6Server) ReleaseLease(ip netip.Addr) error {
	if !s.leases.release(ip) {
		return fmt.Errorf("lease %s not found", ip)
	}
	return nil
}

func (s *dhcp6Server) serverDUID() dhcpv6.DUID {
	return &dhcpv6.DUIDLL{
		HWType:        iana.HWTypeEthernet,
		LinkLayerAddr: s.env.mac(),
	}
}

// handleFrame consumes UDP :547 packets.
func (s *dhcp6Server) handleFrame(pkt packet.Ingress) bool {
	if !pkt.IsUDP6 || pkt.DstPort != dhcp6ServerPort {
		return false
	}
	cfg := s.config()
	prefix, ok := s.env.v6()
	if !cfg.Enabled || !ok {
		return true
	}

	d, err := dhcpv6.FromBytes(pkt.Payload)
	if err != nil {
		return true
	}
	msg, ok2 := d.(*dhcpv6.Message)
	if !ok2 {
		return true // relay messages unsupported
	}
	clientID := msg.Options.ClientID()
	if clientID == nil {
		return true
	}

	switch msg.MessageType {
	case dhcpv6.MessageTypeSolicit:
		s.replyAddress(cfg, prefix, pkt, msg, true)
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind:
		s.replyAddress(cfg, prefix, pkt, msg, false)
	case dhcpv6.MessageTypeRelease:
		duidHex := hex.EncodeToString(clientID.ToBytes())
		if l := s.leases.byClient(pkt.SrcMAC.String(), duidHex); l != nil {
			s.leases.release(l.IP)
		}
		s.replyStatus(pkt, msg)
	case dhcpv6.MessageTypeInformationRequest:
		s.replyInformation(cfg, prefix, pkt, msg)
	}
	return true
}

// selectIP6 picks (and books) the client's address.
func (s *dhcp6Server) selectIP6(cfg DHCP6Config, prefix netip.Prefix, srcMAC net.HardwareAddr, duidHex, hostname string) netip.Addr {
	mac := srcMAC.String()
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
		ClientID: duidHex,
		Hostname: hostname,
		Expiry:   time.Now().Add(cfg.LeaseTime),
	}

	if b := matchBinding(bindings, mac, duidHex); b != nil {
		ip := addrAtOffset(prefix, b.Offset)
		if ip.IsValid() {
			if s.leases.inUse(ip, mac, duidHex) {
				return netip.Addr{}
			}
			lease.IP = ip
			lease.Static = true
			s.leases.set(lease)
			return ip
		}
	}

	if cur := s.leases.byClient(mac, duidHex); cur != nil && !staticIPs[cur.IP] && prefix.Masked().Contains(cur.IP) {
		lease.IP = cur.IP
		s.leases.set(lease)
		return cur.IP
	}

	if !poolStart.IsValid() || !poolEnd.IsValid() {
		return netip.Addr{}
	}

	return s.leases.allocate(poolStart, poolEnd, func(ip netip.Addr) bool {
		return ip == gwIP || staticIPs[ip]
	}, lease)
}

func hostnameOf(msg *dhcpv6.Message) string {
	if fqdn := msg.Options.FQDN(); fqdn != nil && fqdn.DomainName != nil && len(fqdn.DomainName.Labels) > 0 {
		return fqdn.DomainName.Labels[0]
	}
	return ""
}

// replyAddress answers SOLICIT (advertise=true) and REQUEST/RENEW/REBIND.
func (s *dhcp6Server) replyAddress(cfg DHCP6Config, prefix netip.Prefix, pkt packet.Ingress, msg *dhcpv6.Message, advertise bool) {
	duidHex := hex.EncodeToString(msg.Options.ClientID().ToBytes())
	ip := s.selectIP6(cfg, prefix, pkt.SrcMAC, duidHex, hostnameOf(msg))
	if !ip.IsValid() {
		return
	}

	iaNA := msg.Options.OneIANA()
	mods := []dhcpv6.Modifier{
		dhcpv6.WithServerID(s.serverDUID()),
		dhcpv6.WithDNS(s.dnsServers(cfg, prefix)...),
	}
	if iaNA != nil {
		mods = append(mods, dhcpv6.WithIANA(dhcpv6.OptIAAddress{
			IPv6Addr:          ip.AsSlice(),
			PreferredLifetime: cfg.LeaseTime / 2,
			ValidLifetime:     cfg.LeaseTime,
		}))
	}

	var (
		reply *dhcpv6.Message
		err   error
	)
	if advertise {
		reply, err = dhcpv6.NewAdvertiseFromSolicit(msg, mods...)
	} else {
		reply, err = dhcpv6.NewReplyFromMessage(msg, mods...)
	}
	if err != nil {
		return
	}
	if iaNA != nil {
		// Preserve the client's IAID.
		if ia := reply.Options.OneIANA(); ia != nil {
			ia.IaId = iaNA.IaId
		}
	}
	s.transmit(pkt, reply)
}

func (s *dhcp6Server) dnsServers(cfg DHCP6Config, prefix netip.Prefix) []net.IP {
	if len(cfg.DNS) == 0 {
		return []net.IP{prefix.Addr().AsSlice()}
	}
	out := make([]net.IP, 0, len(cfg.DNS))
	for _, a := range cfg.DNS {
		out = append(out, a.AsSlice())
	}
	return out
}

func (s *dhcp6Server) replyStatus(pkt packet.Ingress, msg *dhcpv6.Message) {
	reply, err := dhcpv6.NewReplyFromMessage(msg, dhcpv6.WithServerID(s.serverDUID()))
	if err != nil {
		return
	}
	s.transmit(pkt, reply)
}

func (s *dhcp6Server) replyInformation(cfg DHCP6Config, prefix netip.Prefix, pkt packet.Ingress, msg *dhcpv6.Message) {
	reply, err := dhcpv6.NewReplyFromMessage(msg,
		dhcpv6.WithServerID(s.serverDUID()),
		dhcpv6.WithDNS(s.dnsServers(cfg, prefix)...),
	)
	if err != nil {
		return
	}
	s.transmit(pkt, reply)
}

// transmit unicasts the reply to the client's link-local address.
func (s *dhcp6Server) transmit(pkt packet.Ingress, reply *dhcpv6.Message) {
	srcIP := s.env.linkLocal()
	if !srcIP.IsValid() {
		return
	}
	frame := packet.CraftUDP6(s.env.mac(), pkt.SrcMAC, srcIP.AsSlice(), pkt.SrcIP,
		dhcp6ServerPort, dhcp6ClientPort, reply.ToBytes())
	_ = s.env.write(frame)
}
