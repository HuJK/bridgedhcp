// Package transport provides the raw L2 attachment to a served interface:
// an AF_PACKET socket with a cBPF filter that admits only DHCPv4 (UDP dst
// 67), DHCPv6 (UDP dst 547) and ICMPv6 router solicitations.
package transport

import (
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const acceptLen = 0x40000

// filterProgram admits untagged DHCPv4/DHCPv6/RS frames only. The VLAN
// check is load-bearing on a main bridge that doubles as trunk backbone:
// the kernel strips 802.1q tags into skb metadata before socket filters
// run (skb_vlan_untag), so without the ancillary vlan_tag_present test a
// *tagged* VLAN's DHCP would look untagged and be answered by the
// untagged domain's server.
func filterProgram() []bpf.RawInstruction {
	prog := []bpf.Instruction{
		/* -2 */ bpf.LoadExtension{Num: bpf.ExtVLANTagPresent},
		/* -1 */ bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0, SkipTrue: 18, SkipFalse: 0}, // tagged -> drop
		/* 0 */ bpf.LoadAbsolute{Off: 12, Size: 2}, // ethertype
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86DD, SkipTrue: 0, SkipFalse: 7},
		// IPv6
		/* 2 */ bpf.LoadAbsolute{Off: 20, Size: 1}, // next header
		/* 3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 2},
		/* 4 */ bpf.LoadAbsolute{Off: 56, Size: 2}, // UDP dst port
		/* 5 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 547, SkipTrue: 11, SkipFalse: 12},
		/* 6 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipTrue: 0, SkipFalse: 11},
		/* 7 */ bpf.LoadAbsolute{Off: 54, Size: 1}, // ICMPv6 type
		/* 8 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 133, SkipTrue: 8, SkipFalse: 9},
		// IPv4
		/* 9 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 8},
		/* 10 */ bpf.LoadAbsolute{Off: 23, Size: 1}, // protocol
		/* 11 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 6},
		/* 12 */ bpf.LoadAbsolute{Off: 20, Size: 2}, // flags+fragment offset
		/* 13 */ bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1FFF, SkipTrue: 4, SkipFalse: 0},
		/* 14 */ bpf.LoadMemShift{Off: 14}, // X = IPv4 header length
		/* 15 */ bpf.LoadIndirect{Off: 16, Size: 2}, // UDP dst port
		/* 16 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 67, SkipTrue: 0, SkipFalse: 1},
		/* 17 */ bpf.RetConstant{Val: acceptLen},
		/* 18 */ bpf.RetConstant{Val: 0},
	}
	raw, err := bpf.Assemble(prog)
	if err != nil {
		panic(fmt.Sprintf("bpf assemble: %v", err)) // static program, cannot fail
	}
	return raw
}

var rawFilter = filterProgram()

// Conn is a filtered AF_PACKET socket on one interface.
type Conn struct {
	fd      int
	ifindex int

	mu     sync.Mutex
	closed bool
}

// Open attaches to the named interface. The filter is installed before the
// socket is bound, so unfiltered frames are never queued.
func Open(ifname string) (*Conn, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifname, err)
	}
	// protocol 0 at socket() time: no packets are delivered until bind
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("packet socket: %w", err)
	}
	filters := make([]unix.SockFilter, len(rawFilter))
	for i, ins := range rawFilter {
		filters[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	prog := unix.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("attach filter: %w", err)
	}
	// promisc membership: virtual devices (bridge/veth) deliver multicast
	// regardless, but this keeps behavior uniform; it is dropped on close
	mreq := unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_PROMISC}
	_ = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
	sll := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, sll); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", ifname, err)
	}
	return &Conn{fd: fd, ifindex: ifi.Index}, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Read blocks for the next admitted frame. Returns unix.EBADF-wrapped errors
// after Close.
func (c *Conn) Read(buf []byte) (int, error) {
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		return n, nil
	}
}

// Write transmits one raw frame on the interface.
func (c *Conn) Write(frame []byte) error {
	if len(frame) < 14 {
		return fmt.Errorf("short frame")
	}
	var addr [8]byte
	copy(addr[:], frame[0:6])
	sll := &unix.SockaddrLinklayer{
		Ifindex: c.ifindex,
		Halen:   6,
		Addr:    addr,
	}
	return unix.Sendto(c.fd, frame, 0, sll)
}

// Close shuts the socket down; a blocked Read returns with an error.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	// shutdown wakes a blocked Recvfrom before close invalidates the fd
	_ = unix.Shutdown(c.fd, unix.SHUT_RDWR)
	return unix.Close(c.fd)
}

// Ifindex returns the bound interface index.
func (c *Conn) Ifindex() int { return c.ifindex }
