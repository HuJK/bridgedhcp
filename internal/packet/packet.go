// Package packet crafts and parses the few frame shapes bridgedhcp needs
// (DHCP replies, router advertisements) without a netstack dependency.
//
// Frames received off a tap/bridge may carry CHECKSUM_PARTIAL L4 checksums
// (virtio TX offload); parsing therefore never validates checksums. Frames
// we transmit always carry fully computed checksums.
package packet

import (
	"encoding/binary"
	"net"
)

const (
	EthHeaderSize  = 14
	IPv4MinSize    = 20
	IPv6HeaderSize = 40
	UDPHeaderSize  = 8

	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD

	ProtoUDP    = 17
	ProtoICMPv6 = 58

	ICMPv6TypeRouterSolicit = 133
	ICMPv6TypeRouterAdvert  = 134
)

// checksumFold sums data into the running one's-complement sum.
func checksumAdd(sum uint32, data []byte) uint32 {
	n := len(data)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if n%2 == 1 {
		sum += uint32(data[n-1]) << 8
	}
	return sum
}

func checksumFinish(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// pseudoHeaderSum computes the IPv4/IPv6 pseudo-header sum for proto/length.
func pseudoHeaderSum(srcIP, dstIP net.IP, proto uint8, l4len int) uint32 {
	var sum uint32
	sum = checksumAdd(sum, srcIP)
	sum = checksumAdd(sum, dstIP)
	sum += uint32(proto)
	sum += uint32(l4len)
	return sum
}

// CraftUDP4 builds an ethernet/IPv4/UDP frame with full checksums.
func CraftUDP4(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	src4, dst4 := srcIP.To4(), dstIP.To4()
	udpLen := UDPHeaderSize + len(payload)
	frame := make([]byte, EthHeaderSize+IPv4MinSize+udpLen)

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeIPv4)

	ip := frame[EthHeaderSize:]
	ip[0] = 0x45 // v4, 20-byte header
	binary.BigEndian.PutUint16(ip[2:4], uint16(IPv4MinSize+udpLen))
	ip[8] = 64 // TTL
	ip[9] = ProtoUDP
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)
	binary.BigEndian.PutUint16(ip[10:12], checksumFinish(checksumAdd(0, ip[:IPv4MinSize])))

	udp := ip[IPv4MinSize:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[UDPHeaderSize:], payload)
	sum := pseudoHeaderSum(src4, dst4, ProtoUDP, udpLen)
	sum = checksumAdd(sum, udp[:udpLen])
	csum := checksumFinish(sum)
	if csum == 0 {
		csum = 0xFFFF // RFC 768: zero means "no checksum"
	}
	binary.BigEndian.PutUint16(udp[6:8], csum)

	return frame
}

// CraftUDP6 builds an ethernet/IPv6/UDP frame with full checksums.
func CraftUDP6(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	src6, dst6 := srcIP.To16(), dstIP.To16()
	udpLen := UDPHeaderSize + len(payload)
	frame := make([]byte, EthHeaderSize+IPv6HeaderSize+udpLen)

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeIPv6)

	ip := frame[EthHeaderSize:]
	ip[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(udpLen))
	ip[6] = ProtoUDP
	ip[7] = 64 // hop limit
	copy(ip[8:24], src6)
	copy(ip[24:40], dst6)

	udp := ip[IPv6HeaderSize:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[UDPHeaderSize:], payload)
	sum := pseudoHeaderSum(src6, dst6, ProtoUDP, udpLen)
	sum = checksumAdd(sum, udp[:udpLen])
	csum := checksumFinish(sum)
	if csum == 0 {
		csum = 0xFFFF
	}
	binary.BigEndian.PutUint16(udp[6:8], csum)

	return frame
}

// CraftICMP6 builds an ethernet/IPv6/ICMPv6 frame (for RA). icmpBody starts
// at the ICMPv6 type byte; its checksum field is computed here.
func CraftICMP6(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, icmpBody []byte, hopLimit uint8) []byte {
	src6, dst6 := srcIP.To16(), dstIP.To16()
	frame := make([]byte, EthHeaderSize+IPv6HeaderSize+len(icmpBody))

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeIPv6)

	ip := frame[EthHeaderSize:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(icmpBody)))
	ip[6] = ProtoICMPv6
	ip[7] = hopLimit
	copy(ip[8:24], src6)
	copy(ip[24:40], dst6)

	icmp := ip[IPv6HeaderSize:]
	copy(icmp, icmpBody)
	icmp[2], icmp[3] = 0, 0
	sum := pseudoHeaderSum(src6, dst6, ProtoICMPv6, len(icmpBody))
	sum = checksumAdd(sum, icmp[:len(icmpBody)])
	binary.BigEndian.PutUint16(icmp[2:4], checksumFinish(sum))

	return frame
}

// Ingress is a parsed inbound frame, dissected just far enough to dispatch
// DHCPv4/DHCPv6/router-solicitation traffic.
type Ingress struct {
	SrcMAC  net.HardwareAddr
	IsUDP4  bool
	IsUDP6  bool
	IsICMP6 bool
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16 // UDP
	DstPort uint16 // UDP
	ICMPTyp uint8  // ICMPv6
	Payload []byte // UDP payload or full ICMPv6 message
}

// Parse dissects an untagged ethernet frame. Returns ok=false for frames
// that are not UDP4/UDP6/ICMPv6. L4 checksums are intentionally not
// validated (see package comment).
func Parse(frame []byte) (Ingress, bool) {
	var p Ingress
	if len(frame) < EthHeaderSize {
		return p, false
	}
	p.SrcMAC = net.HardwareAddr(append([]byte(nil), frame[6:12]...))
	etherType := binary.BigEndian.Uint16(frame[12:14])
	body := frame[EthHeaderSize:]

	switch etherType {
	case EtherTypeIPv4:
		if len(body) < IPv4MinSize {
			return p, false
		}
		if body[0]>>4 != 4 {
			return p, false
		}
		ihl := int(body[0]&0x0F) * 4
		totalLen := int(binary.BigEndian.Uint16(body[2:4]))
		if ihl < IPv4MinSize || totalLen < ihl || totalLen > len(body) {
			return p, false
		}
		// no fragments: DHCP fits in one frame
		fragField := binary.BigEndian.Uint16(body[6:8])
		if fragField&0x3FFF != 0 { // MF flag or fragment offset
			return p, false
		}
		if body[9] != ProtoUDP {
			return p, false
		}
		udp := body[ihl:totalLen]
		if len(udp) < UDPHeaderSize {
			return p, false
		}
		p.IsUDP4 = true
		p.SrcIP = net.IP(append([]byte(nil), body[12:16]...))
		p.DstIP = net.IP(append([]byte(nil), body[16:20]...))
		p.SrcPort = binary.BigEndian.Uint16(udp[0:2])
		p.DstPort = binary.BigEndian.Uint16(udp[2:4])
		p.Payload = udp[UDPHeaderSize:]
		return p, true

	case EtherTypeIPv6:
		if len(body) < IPv6HeaderSize {
			return p, false
		}
		if body[0]>>4 != 6 {
			return p, false
		}
		payloadLen := int(binary.BigEndian.Uint16(body[4:6]))
		if IPv6HeaderSize+payloadLen > len(body) {
			return p, false
		}
		p.SrcIP = net.IP(append([]byte(nil), body[8:24]...))
		p.DstIP = net.IP(append([]byte(nil), body[24:40]...))
		rest := body[IPv6HeaderSize : IPv6HeaderSize+payloadLen]
		// next-header chains (hop-by-hop etc.) are not walked: RS/DHCPv6
		// from real clients arrive without extension headers
		switch body[6] {
		case ProtoUDP:
			if len(rest) < UDPHeaderSize {
				return p, false
			}
			p.IsUDP6 = true
			p.SrcPort = binary.BigEndian.Uint16(rest[0:2])
			p.DstPort = binary.BigEndian.Uint16(rest[2:4])
			p.Payload = rest[UDPHeaderSize:]
			return p, true
		case ProtoICMPv6:
			if len(rest) < 4 {
				return p, false
			}
			p.IsICMP6 = true
			p.ICMPTyp = rest[0]
			p.Payload = rest
			return p, true
		}
	}
	return p, false
}
