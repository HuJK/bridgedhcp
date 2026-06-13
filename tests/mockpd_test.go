//go:build integration

package tests

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"golang.org/x/net/ipv6"
)

// mockPD is a minimal DHCPv6-PD server running inside a namespace. It
// delegates one fixed prefix and records which message types it saw, so
// tests can assert "roaming used REBIND, not a fresh SOLICIT".
type mockPD struct {
	prefix    netip.Prefix
	valid     time.Duration
	conn      *net.UDPConn
	answering atomic.Bool

	mu   sync.Mutex
	seen []dhcpv6.MessageType
}

// startMockPD binds :547 on ifname inside ns and serves.
func startMockPD(t *testing.T, ns, ifname string, prefix netip.Prefix, valid time.Duration) *mockPD {
	t.Helper()
	m := &mockPD{prefix: prefix, valid: valid}
	m.answering.Store(true)

	runInNS(t, ns, func() error {
		conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 547})
		if err != nil {
			return err
		}
		ifi, err := net.InterfaceByName(ifname)
		if err != nil {
			conn.Close()
			return err
		}
		p := ipv6.NewPacketConn(conn)
		if err := p.JoinGroup(ifi, &net.UDPAddr{IP: net.ParseIP("ff02::1:2")}); err != nil {
			conn.Close()
			return err
		}
		m.conn = conn
		return nil
	})
	go m.serve()
	t.Cleanup(func() { m.conn.Close() })
	return m
}

func (m *mockPD) serve() {
	buf := make([]byte, 1500)
	for {
		n, peer, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		parsed, err := dhcpv6.FromBytes(buf[:n])
		if err != nil {
			continue
		}
		msg, ok := parsed.(*dhcpv6.Message)
		if !ok {
			continue
		}
		m.mu.Lock()
		m.seen = append(m.seen, msg.MessageType)
		m.mu.Unlock()
		if !m.answering.Load() {
			continue
		}
		reply := m.buildReply(msg)
		if reply != nil {
			_, _ = m.conn.WriteToUDP(reply.ToBytes(), peer)
		}
	}
}

func (m *mockPD) serverDUID() dhcpv6.DUID {
	return &dhcpv6.DUIDLL{
		HWType:        iana.HWTypeEthernet,
		LinkLayerAddr: net.HardwareAddr{0x02, 0xbd, 0, 0, 0, 1},
	}
}

func (m *mockPD) buildReply(msg *dhcpv6.Message) *dhcpv6.Message {
	clientID := msg.Options.ClientID()
	if clientID == nil {
		return nil
	}
	reqIAPD := msg.Options.OneIAPD()
	if reqIAPD == nil {
		return nil
	}

	var typ dhcpv6.MessageType
	switch msg.MessageType {
	case dhcpv6.MessageTypeSolicit:
		typ = dhcpv6.MessageTypeAdvertise
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind:
		typ = dhcpv6.MessageTypeReply
	default:
		return nil
	}

	iapd := &dhcpv6.OptIAPD{IaId: reqIAPD.IaId, T1: m.valid / 2, T2: m.valid * 4 / 5}
	iapd.Options.Add(&dhcpv6.OptIAPrefix{
		PreferredLifetime: m.valid / 2,
		ValidLifetime:     m.valid,
		Prefix: &net.IPNet{
			IP:   m.prefix.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(m.prefix.Bits(), 128),
		},
	})

	reply := &dhcpv6.Message{MessageType: typ, TransactionID: msg.TransactionID}
	reply.AddOption(dhcpv6.OptClientID(clientID))
	reply.AddOption(dhcpv6.OptServerID(m.serverDUID()))
	reply.AddOption(iapd)
	return reply
}

// sawType reports whether a message type was received.
func (m *mockPD) sawType(typ dhcpv6.MessageType) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.seen {
		if s == typ {
			return true
		}
	}
	return false
}

// resetSeen clears the message log.
func (m *mockPD) resetSeen() {
	m.mu.Lock()
	m.seen = nil
	m.mu.Unlock()
}
