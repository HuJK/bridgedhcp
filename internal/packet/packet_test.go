package packet

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// refChecksum is an independent one's-complement implementation used to
// cross-check the production code.
func refChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}

func TestCraftUDP4Roundtrip(t *testing.T) {
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	payload := []byte("hello dhcp")
	frame := CraftUDP4(srcMAC, dstMAC,
		net.ParseIP("192.168.1.1"), net.ParseIP("255.255.255.255"),
		67, 68, payload)

	pkt, ok := Parse(frame)
	if !ok || !pkt.IsUDP4 {
		t.Fatalf("parse failed: %+v ok=%v", pkt, ok)
	}
	if pkt.SrcPort != 67 || pkt.DstPort != 68 {
		t.Fatalf("ports: %d -> %d", pkt.SrcPort, pkt.DstPort)
	}
	if !bytes.Equal(pkt.Payload, payload) {
		t.Fatalf("payload mismatch")
	}
	if pkt.SrcIP.String() != "192.168.1.1" {
		t.Fatalf("src ip %s", pkt.SrcIP)
	}

	// verify the IPv4 header checksum independently
	ip := frame[EthHeaderSize : EthHeaderSize+IPv4MinSize]
	cp := append([]byte(nil), ip...)
	cp[10], cp[11] = 0, 0
	want := refChecksum(cp)
	got := binary.BigEndian.Uint16(ip[10:12])
	if got != want {
		t.Fatalf("ipv4 checksum got %04x want %04x", got, want)
	}

	// verify the UDP checksum independently (pseudo header + segment)
	udp := frame[EthHeaderSize+IPv4MinSize:]
	pseudo := make([]byte, 0, 12+len(udp))
	pseudo = append(pseudo, ip[12:16]...)
	pseudo = append(pseudo, ip[16:20]...)
	pseudo = append(pseudo, 0, ProtoUDP)
	pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(udp)))
	seg := append([]byte(nil), udp...)
	seg[6], seg[7] = 0, 0
	pseudo = append(pseudo, seg...)
	want = refChecksum(pseudo)
	got = binary.BigEndian.Uint16(udp[6:8])
	if got != want {
		t.Fatalf("udp checksum got %04x want %04x", got, want)
	}
}

func TestCraftUDP6Roundtrip(t *testing.T) {
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	payload := []byte("dhcpv6 message body")
	frame := CraftUDP6(srcMAC, dstMAC,
		net.ParseIP("fe80::1"), net.ParseIP("fe80::2"),
		547, 546, payload)

	pkt, ok := Parse(frame)
	if !ok || !pkt.IsUDP6 {
		t.Fatalf("parse failed")
	}
	if pkt.SrcPort != 547 || pkt.DstPort != 546 {
		t.Fatalf("ports: %d -> %d", pkt.SrcPort, pkt.DstPort)
	}
	if !bytes.Equal(pkt.Payload, payload) {
		t.Fatalf("payload mismatch")
	}

	ip := frame[EthHeaderSize : EthHeaderSize+IPv6HeaderSize]
	udp := frame[EthHeaderSize+IPv6HeaderSize:]
	pseudo := make([]byte, 0, 40+len(udp))
	pseudo = append(pseudo, ip[8:24]...)
	pseudo = append(pseudo, ip[24:40]...)
	pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(udp)))
	pseudo = append(pseudo, 0, 0, 0, ProtoUDP)
	seg := append([]byte(nil), udp...)
	seg[6], seg[7] = 0, 0
	pseudo = append(pseudo, seg...)
	want := refChecksum(pseudo)
	got := binary.BigEndian.Uint16(udp[6:8])
	if got != want {
		t.Fatalf("udp6 checksum got %04x want %04x", got, want)
	}
}

func TestCraftICMP6Checksum(t *testing.T) {
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	body := []byte{ICMPv6TypeRouterAdvert, 0, 0, 0, 64, 0, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0}
	frame := CraftICMP6(srcMAC, net.HardwareAddr{0x33, 0x33, 0, 0, 0, 1},
		net.ParseIP("fe80::1"), net.ParseIP("ff02::1"), body, 255)

	pkt, ok := Parse(frame)
	if !ok || !pkt.IsICMP6 || pkt.ICMPTyp != ICMPv6TypeRouterAdvert {
		t.Fatalf("parse failed: %+v", pkt)
	}

	ip := frame[EthHeaderSize : EthHeaderSize+IPv6HeaderSize]
	icmp := frame[EthHeaderSize+IPv6HeaderSize:]
	pseudo := make([]byte, 0, 40+len(icmp))
	pseudo = append(pseudo, ip[8:24]...)
	pseudo = append(pseudo, ip[24:40]...)
	pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(icmp)))
	pseudo = append(pseudo, 0, 0, 0, ProtoICMPv6)
	seg := append([]byte(nil), icmp...)
	seg[2], seg[3] = 0, 0
	pseudo = append(pseudo, seg...)
	want := refChecksum(pseudo)
	got := binary.BigEndian.Uint16(icmp[2:4])
	if got != want {
		t.Fatalf("icmp6 checksum got %04x want %04x", got, want)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, ok := Parse([]byte{1, 2, 3}); ok {
		t.Fatal("short frame accepted")
	}
	junk := make([]byte, 64)
	junk[12], junk[13] = 0x08, 0x06 // ARP
	if _, ok := Parse(junk); ok {
		t.Fatal("arp accepted")
	}
}

func TestParseRejectsFragments(t *testing.T) {
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02")
	frame := CraftUDP4(srcMAC, dstMAC,
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 67, 68, []byte("x"))
	binary.BigEndian.PutUint16(frame[EthHeaderSize+6:], 0x2000) // MF set
	if _, ok := Parse(frame); ok {
		t.Fatal("fragment accepted")
	}
}
