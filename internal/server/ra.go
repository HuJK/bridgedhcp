package server

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/HuJK/bridgedhcp/internal/packet"
)

const (
	defaultRAInterval        = 200 * time.Second
	defaultRouterLifetime    = 1800 * time.Second
	defaultValidLifetime     = 30 * 24 * time.Hour
	defaultPreferredLifetime = 7 * 24 * time.Hour
	ndpHopLimit              = 255
	deprecateResends         = 3
)

var (
	allNodesIP6 = net.ParseIP("ff02::1")
	allNodesMAC = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
)

// RAConfig configures router advertisements for one interface.
type RAConfig struct {
	Enabled        bool // advertise at all (SLAAC or DHCPv6-managed)
	Autonomous     bool // SLAAC: clients self-assign from the prefix (A flag)
	Managed        bool // M flag: addresses via DHCPv6
	Other          bool // O flag: other config via DHCPv6
	Interval       time.Duration
	RouterLifetime time.Duration
	ValidLifetime  time.Duration
	PreferredLife  time.Duration
	DNS            []netip.Addr // RDNSS; empty: the interface link-local
}

func (c *RAConfig) normalize() {
	if c.Interval <= 0 {
		c.Interval = defaultRAInterval
	}
	if c.RouterLifetime <= 0 {
		c.RouterLifetime = defaultRouterLifetime
	}
	if c.ValidLifetime <= 0 {
		c.ValidLifetime = defaultValidLifetime
	}
	if c.PreferredLife <= 0 {
		c.PreferredLife = defaultPreferredLifetime
	}
}

// raServer broadcasts periodic RAs and answers router solicitations. The
// advertised prefixes are the interface's live global /64s; when one
// disappears (PD loss) it is advertised a few more times with zero
// lifetimes so clients deprecate it immediately.
type raServer struct {
	env *env

	mu        sync.Mutex
	cfg       RAConfig
	last      []netip.Prefix // prefixes advertised in the previous RA
	deprecate map[netip.Prefix]int
	kick      chan struct{}
}

func newRAServer(e *env, cfg RAConfig) *raServer {
	cfg.normalize()
	s := &raServer{
		env:       e,
		cfg:       cfg,
		deprecate: make(map[netip.Prefix]int),
		kick:      make(chan struct{}, 1),
	}
	go s.loop()
	return s
}

func (s *raServer) config() RAConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Kick re-evaluates prefixes now (after an address change).
func (s *raServer) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *raServer) loop() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		cfg := s.config()
		if cfg.Enabled {
			s.send(cfg, allNodesMAC, allNodesIP6)
			timer.Reset(cfg.Interval)
		} else {
			timer.Reset(time.Hour)
		}

		select {
		case <-s.env.done:
			// final RA: router lifetime 0 so clients drop the route
			if cfg.Enabled {
				s.sendFinal(cfg)
			}
			return
		case <-s.kick:
		case <-timer.C:
		}
	}
}

// handleFrame answers router solicitations (ICMPv6 type 133).
func (s *raServer) handleFrame(pkt packet.Ingress) bool {
	if !pkt.IsICMP6 || pkt.ICMPTyp != packet.ICMPv6TypeRouterSolicit {
		return false
	}
	cfg := s.config()
	if !cfg.Enabled {
		return true
	}
	dstMAC, dstIP := allNodesMAC, allNodesIP6
	if !pkt.SrcIP.IsUnspecified() {
		dstMAC, dstIP = pkt.SrcMAC, pkt.SrcIP
	}
	s.send(cfg, dstMAC, dstIP)
	return true
}

// currentPrefixes merges live /64s with prefixes pending deprecation.
// Returned map value true = alive, false = deprecate (zero lifetimes).
func (s *raServer) currentPrefixes() map[netip.Prefix]bool {
	live := make(map[netip.Prefix]bool)
	for _, p := range s.env.v6all() {
		if p.Bits() == 64 {
			live[p.Masked()] = true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// prefixes that vanished since the last RA get queued for deprecation
	for _, p := range s.last {
		if !live[p] {
			if _, pending := s.deprecate[p]; !pending {
				s.deprecate[p] = deprecateResends
			}
		}
	}
	out := make(map[netip.Prefix]bool, len(live)+len(s.deprecate))
	for p := range live {
		out[p] = true
		delete(s.deprecate, p) // came back: stop deprecating
	}
	for p, n := range s.deprecate {
		out[p] = false
		if n <= 1 {
			delete(s.deprecate, p)
		} else {
			s.deprecate[p] = n - 1
		}
	}
	s.last = s.last[:0]
	for p := range live {
		s.last = append(s.last, p)
	}
	return out
}

// send crafts and transmits one RA.
func (s *raServer) send(cfg RAConfig, dstMAC net.HardwareAddr, dstIP net.IP) {
	prefixes := s.currentPrefixes()
	s.transmitRA(cfg, dstMAC, dstIP, prefixes, uint16(cfg.RouterLifetime/time.Second))
}

// sendFinal advertises router lifetime 0 (shutdown).
func (s *raServer) sendFinal(cfg RAConfig) {
	prefixes := make(map[netip.Prefix]bool)
	for _, p := range s.env.v6all() {
		if p.Bits() == 64 {
			prefixes[p.Masked()] = false
		}
	}
	s.transmitRA(cfg, allNodesMAC, allNodesIP6, prefixes, 0)
}

func (s *raServer) transmitRA(cfg RAConfig, dstMAC net.HardwareAddr, dstIP net.IP, prefixes map[netip.Prefix]bool, routerLifetime uint16) {
	srcIP := s.env.linkLocal()
	if !srcIP.IsValid() {
		return
	}

	// ICMPv6 RA: 4-byte header + 12-byte RA body, then options
	body := make([]byte, 16, 16+8+len(prefixes)*32+64)
	body[0] = packet.ICMPv6TypeRouterAdvert
	body[4] = 64 // current hop limit suggestion
	if cfg.Managed {
		body[5] |= 1 << 7
	}
	if cfg.Other {
		body[5] |= 1 << 6
	}
	binary.BigEndian.PutUint16(body[6:8], routerLifetime)
	// reachable time and retrans timer: 0 = unspecified

	// option: source link-layer address
	mac := s.env.mac()
	opt := make([]byte, 8)
	opt[0], opt[1] = 1, 1
	copy(opt[2:8], mac)
	body = append(body, opt...)

	// option: prefix information per prefix (RFC 4861 §4.6.2)
	for p, alive := range prefixes {
		pi := make([]byte, 32)
		pi[0], pi[1] = 3, 4
		pi[2] = byte(p.Bits())
		pi[3] = 1 << 7 // on-link
		if cfg.Autonomous {
			pi[3] |= 1 << 6
		}
		if alive {
			binary.BigEndian.PutUint32(pi[4:8], uint32(cfg.ValidLifetime/time.Second))
			binary.BigEndian.PutUint32(pi[8:12], uint32(cfg.PreferredLife/time.Second))
		}
		addr := p.Addr().As16()
		copy(pi[16:32], addr[:])
		body = append(body, pi...)
	}

	// option: RDNSS (RFC 8106) when DNS servers are configured
	if dns := s.rdnss(cfg); len(dns) > 0 {
		rd := make([]byte, 8+16*len(dns))
		rd[0] = 25
		rd[1] = byte(1 + 2*len(dns))
		binary.BigEndian.PutUint32(rd[4:8], uint32(cfg.RouterLifetime/time.Second))
		for i, a := range dns {
			a16 := a.As16()
			copy(rd[8+16*i:], a16[:])
		}
		body = append(body, rd...)
	}

	frame := packet.CraftICMP6(mac, dstMAC, srcIP.AsSlice(), dstIP, body, ndpHopLimit)
	_ = s.env.write(frame)
}

// rdnss: only explicitly configured servers are advertised — guessing a
// default here would announce a resolver that may not exist.
func (s *raServer) rdnss(cfg RAConfig) []netip.Addr {
	return cfg.DNS
}
