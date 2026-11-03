package capture

import (
	"encoding/binary"
	"net/netip"
)

// Protocol numbers we care about.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// Packet is the small summary we keep of each packet header.
type Packet struct {
	IP               bool // false for ARP and other non-IP frames
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	Proto            uint8
	TCPFlags         uint8 // SYN = 0x02, ACK = 0x10 ...

	// ARP frames (IP is false for them). The sender's IP is stored in Src.
	ARP    bool
	ARPOp  uint16  // 1 = request, 2 = reply
	ARPMAC [6]byte // sender hardware address
}

// Parse reads an Ethernet frame (optionally VLAN tagged) and extracts the
// IP addresses, protocol and TCP/UDP ports. It never allocates.
func Parse(b []byte) Packet {
	var p Packet
	if len(b) < 14 {
		return p
	}
	et := binary.BigEndian.Uint16(b[12:14])
	off := 14
	for (et == 0x8100 || et == 0x88a8) && len(b) >= off+4 { // VLAN tags
		et = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	switch et {
	case 0x0800:
		parseV4(b[off:], &p)
	case 0x86dd:
		parseV6(b[off:], &p)
	case 0x0806:
		parseARP(b[off:], &p)
	}
	return p
}

func readPorts(b []byte, p *Packet) {
	if (p.Proto == ProtoTCP || p.Proto == ProtoUDP) && len(b) >= 4 {
		p.SrcPort = binary.BigEndian.Uint16(b[0:2])
		p.DstPort = binary.BigEndian.Uint16(b[2:4])
	}
	if p.Proto == ProtoTCP && len(b) >= 14 {
		p.TCPFlags = b[13]
	}
}

// parseARP reads an Ethernet/IPv4 ARP message.
func parseARP(b []byte, p *Packet) {
	if len(b) < 28 || b[4] != 6 || b[5] != 4 || binary.BigEndian.Uint16(b[2:4]) != 0x0800 {
		return
	}
	p.ARP = true
	p.ARPOp = binary.BigEndian.Uint16(b[6:8])
	copy(p.ARPMAC[:], b[8:14])
	var ip [4]byte
	copy(ip[:], b[14:18])
	p.Src = netip.AddrFrom4(ip)
}

func parseV4(b []byte, p *Packet) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return
	}
	var s, d [4]byte
	copy(s[:], b[12:16])
	copy(d[:], b[16:20])
	p.IP = true
	p.Src, p.Dst = netip.AddrFrom4(s), netip.AddrFrom4(d)
	p.Proto = b[9]
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return // later fragment: no TCP/UDP header inside
	}
	readPorts(b[ihl:], p)
}

func parseV6(b []byte, p *Packet) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return
	}
	var s, d [16]byte
	copy(s[:], b[8:24])
	copy(d[:], b[24:40])
	p.IP = true
	p.Src, p.Dst = netip.AddrFrom16(s), netip.AddrFrom16(d)
	next, off := b[6], 40
	for i := 0; i < 4 && (next == 0 || next == 43 || next == 60 || next == 44); i++ {
		if len(b) < off+8 {
			p.Proto = next
			return
		}
		if next == 44 { // fragment header
			if binary.BigEndian.Uint16(b[off+2:off+4])&0xfff8 != 0 {
				p.Proto = b[off]
				return
			}
			next, off = b[off], off+8
		} else { // hop-by-hop, routing, destination options
			next, off = b[off], off+(int(b[off+1])+1)*8
		}
	}
	p.Proto = next
	if off < len(b) {
		readPorts(b[off:], p)
	}
}
