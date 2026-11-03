package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
)

// Traffic direction, seen from your network.
const (
	DirUp    = "up"    // your network -> internet
	DirDown  = "down"  // internet -> your network
	DirLAN   = "lan"   // device <-> device on your network
	DirOther = "other" // IPv6 internet traffic, non-IP frames, unknown
)

var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

type FlowKey struct {
	Src, Dst netip.Addr
	Port     uint16 // service port (the lower of the two ports)
	Proto    uint8
}

type flowVal struct {
	bytes, packets uint64
	dir            string
}

// FlowRow is one summarized flow, ready to be saved.
type FlowRow struct {
	Src, Dst       string
	Port           int
	Proto, Dir     string
	Bytes, Packets uint64
}

// Sample is the traffic of one time slice, in bytes.
type Sample struct{ Down, Up, Lan, Other, Packets uint64 }

func (s *Sample) add(o Sample) {
	s.Down += o.Down
	s.Up += o.Up
	s.Lan += o.Lan
	s.Other += o.Other
	s.Packets += o.Packets
}

// Talker is the traffic of one device on your network.
type Talker struct {
	IP                         string
	Sent, Recv                 uint64
	SentRate, RecvRate         uint64 // bytes in the last second
}

type talker struct{ sent, recv, sentCur, recvCur, sentRate, recvRate uint64 }

// Snapshot is a copy of the current counters.
type Snapshot struct {
	Total   Sample
	Dropped uint64 // packets not tracked as separate flows because the table was full
	Talkers []Talker
}

// Aggregator turns packets into flows in memory, with a hard size limit.
type Aggregator struct {
	mu       sync.Mutex
	base     uint32
	mask     uint32
	maxFlows int
	flows    map[FlowKey]*flowVal
	cur      Sample
	total    Sample
	dropped  uint64
	talkers  map[netip.Addr]*talker
}

// NewAggregator creates an aggregator for the given local IPv4 network.
func NewAggregator(local *net.IPNet, maxFlows int) *Aggregator {
	if maxFlows < 100 {
		maxFlows = 20000
	}
	a := &Aggregator{maxFlows: maxFlows, flows: map[FlowKey]*flowVal{}, talkers: map[netip.Addr]*talker{}}
	if ip4 := local.IP.To4(); ip4 != nil {
		m := local.Mask
		if len(m) == 16 {
			m = m[12:]
		}
		a.mask = binary.BigEndian.Uint32(m)
		a.base = binary.BigEndian.Uint32(ip4) & a.mask
	}
	return a
}

func (a *Aggregator) inSubnet(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	b := ip.As4()
	return binary.BigEndian.Uint32(b[:])&a.mask == a.base
}

// lanSide is true for addresses that belong to your own network, including
// multicast and broadcast chatter that never leaves it.
func (a *Aggregator) lanSide(ip netip.Addr) bool {
	if ip.Is4() {
		return a.inSubnet(ip) || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip == limitedBroadcast
	}
	return ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsLoopback() || ip.IsPrivate()
}

func svcPort(sp, dp uint16) uint16 {
	if sp == 0 {
		return dp
	}
	if dp == 0 {
		return sp
	}
	if dp < sp {
		return dp
	}
	return sp
}

func (a *Aggregator) talkerFor(ip netip.Addr) *talker {
	t := a.talkers[ip]
	if t == nil && len(a.talkers) < 4096 {
		t = &talker{}
		a.talkers[ip] = t
	}
	return t
}

// Add records one packet. wire is its real length in bytes.
func (a *Aggregator) Add(p Packet, wire int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := uint64(wire)
	a.cur.Packets++
	if !p.IP {
		a.cur.Other += n
		return
	}
	sl, dl := a.lanSide(p.Src), a.lanSide(p.Dst)
	var dir string
	switch {
	case sl && dl:
		dir = DirLAN
		a.cur.Lan += n
	case !p.Src.Is4():
		dir = DirOther
		a.cur.Other += n
	case sl:
		dir = DirUp
		a.cur.Up += n
	case dl:
		dir = DirDown
		a.cur.Down += n
	default:
		dir = DirOther
		a.cur.Other += n
	}
	if a.inSubnet(p.Src) {
		if t := a.talkerFor(p.Src); t != nil {
			t.sentCur += n
		}
	}
	if a.inSubnet(p.Dst) {
		if t := a.talkerFor(p.Dst); t != nil {
			t.recvCur += n
		}
	}
	key := FlowKey{Src: p.Src, Dst: p.Dst, Port: svcPort(p.SrcPort, p.DstPort), Proto: p.Proto}
	if f := a.flows[key]; f != nil {
		f.bytes += n
		f.packets++
		return
	}
	if len(a.flows) >= a.maxFlows {
		a.dropped++ // memory cap reached: still counted in the totals above
		return
	}
	a.flows[key] = &flowVal{bytes: n, packets: 1, dir: dir}
}

// Tick closes the current one-second slice and returns it.
func (a *Aggregator) Tick() Sample {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.cur
	a.total.add(s)
	a.cur = Sample{}
	for _, t := range a.talkers {
		t.sent += t.sentCur
		t.recv += t.recvCur
		t.sentRate, t.recvRate = t.sentCur, t.recvCur
		t.sentCur, t.recvCur = 0, 0
	}
	return s
}

// Snapshot returns the totals and per-device traffic since start.
func (a *Aggregator) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Snapshot{Total: a.total, Dropped: a.dropped}
	s.Total.add(a.cur)
	for ip, t := range a.talkers {
		s.Talkers = append(s.Talkers, Talker{IP: ip.String(), Sent: t.sent + t.sentCur, Recv: t.recv + t.recvCur,
			SentRate: t.sentRate, RecvRate: t.recvRate})
	}
	return s
}

func protoName(p uint8) string {
	switch p {
	case ProtoICMP:
		return "icmp"
	case 2:
		return "igmp"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMPv6:
		return "icmpv6"
	}
	return fmt.Sprintf("ip%d", p)
}

// FlushRaw empties the flow table and returns every flow (unsorted).
func (a *Aggregator) FlushRaw() []FlowRow {
	a.mu.Lock()
	old := a.flows
	a.flows = make(map[FlowKey]*flowVal)
	a.mu.Unlock()

	rows := make([]FlowRow, 0, len(old))
	for k, v := range old {
		rows = append(rows, FlowRow{Src: k.Src.String(), Dst: k.Dst.String(), Port: int(k.Port),
			Proto: protoName(k.Proto), Dir: v.dir, Bytes: v.bytes, Packets: v.packets})
	}
	return rows
}

// TrimRows sorts flows biggest first. If there are more than maxRows, the
// smallest ones are added together into one "*" row so the database stays small.
func TrimRows(rows []FlowRow, maxRows int) []FlowRow {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Bytes > rows[j].Bytes })
	if maxRows > 0 && len(rows) > maxRows {
		rest := FlowRow{Src: "*", Dst: "*", Proto: "other", Dir: DirOther}
		for _, r := range rows[maxRows:] {
			rest.Bytes += r.Bytes
			rest.Packets += r.Packets
		}
		rows = append(rows[:maxRows], rest)
	}
	return rows
}

// Flush empties the flow table and returns it, trimmed to maxRows.
func (a *Aggregator) Flush(maxRows int) []FlowRow {
	return TrimRows(a.FlushRaw(), maxRows)
}
