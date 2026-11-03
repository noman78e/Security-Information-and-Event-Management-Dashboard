package capture

import (
	"net"
	"net/netip"
	"testing"
)

// ipv4TCPFrame builds a minimal Ethernet + IPv4 + TCP header for testing.
func ipv4TCPFrame(src, dst [4]byte, sp, dp uint16) []byte {
	b := make([]byte, 14+20+20)
	b[12], b[13] = 0x08, 0x00
	ip := b[14:]
	ip[0] = 0x45
	ip[9] = ProtoTCP
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	ip[20], ip[21] = byte(sp>>8), byte(sp)
	ip[22], ip[23] = byte(dp>>8), byte(dp)
	return b
}

func TestParseIPv4TCP(t *testing.T) {
	p := Parse(ipv4TCPFrame([4]byte{192, 168, 1, 20}, [4]byte{93, 184, 216, 34}, 51000, 443))
	if !p.IP || p.Proto != ProtoTCP || p.SrcPort != 51000 || p.DstPort != 443 {
		t.Fatalf("unexpected packet: %+v", p)
	}
	if p.Src != netip.MustParseAddr("192.168.1.20") || p.Dst != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("wrong addresses: %v -> %v", p.Src, p.Dst)
	}
}

func TestParseNonIP(t *testing.T) {
	arp := make([]byte, 42)
	arp[12], arp[13] = 0x08, 0x06
	if p := Parse(arp); p.IP {
		t.Fatal("ARP must not be reported as IP")
	}
	if p := Parse([]byte{1, 2, 3}); p.IP {
		t.Fatal("short frame must not be reported as IP")
	}
}

func TestDirectionsAndServicePort(t *testing.T) {
	local := &net.IPNet{IP: net.IPv4(192, 168, 1, 0).To4(), Mask: net.CIDRMask(24, 32)}
	a := NewAggregator(local, 1000)
	pc := netip.MustParseAddr("192.168.1.20")
	phone := netip.MustParseAddr("192.168.1.30")
	web := netip.MustParseAddr("93.184.216.34")
	mdns := netip.MustParseAddr("224.0.0.251")

	a.Add(Packet{IP: true, Src: pc, Dst: web, SrcPort: 51000, DstPort: 443, Proto: ProtoTCP}, 1000) // upload
	a.Add(Packet{IP: true, Src: web, Dst: pc, SrcPort: 443, DstPort: 51000, Proto: ProtoTCP}, 2000) // download
	a.Add(Packet{IP: true, Src: pc, Dst: phone, SrcPort: 5000, DstPort: 6000, Proto: ProtoUDP}, 300) // device to device
	a.Add(Packet{IP: true, Src: pc, Dst: mdns, SrcPort: 5353, DstPort: 5353, Proto: ProtoUDP}, 100) // multicast stays local
	a.Add(Packet{IP: false}, 60)                                                                    // ARP

	s := a.Tick()
	if s.Up != 1000 || s.Down != 2000 || s.Lan != 400 || s.Other != 60 || s.Packets != 5 {
		t.Fatalf("wrong sample: %+v", s)
	}

	rows := a.Flush(100)
	for _, r := range rows {
		if r.Dst == "93.184.216.34" || r.Src == "93.184.216.34" {
			if r.Port != 443 {
				t.Fatalf("service port should be 443, got %d", r.Port)
			}
		}
	}
	if len(rows) != 4 {
		t.Fatalf("expected 4 flows, got %d", len(rows))
	}
}

func TestFlowTableIsCapped(t *testing.T) {
	local := &net.IPNet{IP: net.IPv4(192, 168, 1, 0).To4(), Mask: net.CIDRMask(24, 32)}
	a := NewAggregator(local, 100)
	pc := netip.MustParseAddr("192.168.1.20")
	for i := 0; i < 500; i++ {
		dst := netip.AddrFrom4([4]byte{8, 8, byte(i >> 8), byte(i)})
		a.Add(Packet{IP: true, Src: pc, Dst: dst, SrcPort: 40000, DstPort: 443, Proto: ProtoTCP}, 100)
	}
	snap := a.Snapshot()
	if snap.Dropped != 400 {
		t.Fatalf("expected 400 untracked packets, got %d", snap.Dropped)
	}
	if rows := a.Flush(50); len(rows) != 51 { // 50 biggest + 1 summary row
		t.Fatalf("expected 51 rows, got %d", len(rows))
	}
}

func TestParseSYNFlags(t *testing.T) {
	f := ipv4TCPFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 40000, 22)
	f[14+20+13] = 0x02 // SYN
	p := Parse(f)
	if p.TCPFlags&0x12 != 0x02 {
		t.Fatalf("expected a SYN without ACK, flags=%#x", p.TCPFlags)
	}
}

func TestParseARP(t *testing.T) {
	b := make([]byte, 14+28)
	b[12], b[13] = 0x08, 0x06
	a := b[14:]
	a[1], a[2], a[3] = 1, 0x08, 0x00 // hardware type 1, protocol IPv4
	a[4], a[5] = 6, 4
	a[7] = 2 // reply
	copy(a[8:14], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	copy(a[14:18], []byte{192, 168, 1, 1})
	p := Parse(b)
	if !p.ARP || p.IP || p.ARPOp != 2 || p.Src != netip.MustParseAddr("192.168.1.1") ||
		p.ARPMAC != [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} {
		t.Fatalf("bad ARP parse: %+v", p)
	}
}
