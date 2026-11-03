package rules

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"homesiem/capture"
)

// Alert is what a detector reports. The alert manager decides what to do
// with it (severity, quiet period, notification) from the rules file.
type Alert struct {
	Rule     string // which rule's settings apply (enabled, notify, quiet period)
	Label    string // name shown on the Alerts page instead of Rule (optional)
	Severity string // overrides the rule's severity (optional)
	Key      string // what the quiet period is counted per (device, source address...)
	IP       string // address involved, used to find the device
	MAC      string
	Message  string
}

func samplePorts(set map[uint16]struct{}) string {
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, int(p))
	}
	sort.Ints(ports)
	if len(ports) > 6 {
		ports = ports[:6]
	}
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

func ipListContains(list []string, ip netip.Addr) bool {
	for _, s := range list {
		s = strings.TrimSpace(s)
		if p, err := netip.ParsePrefix(s); err == nil {
			if p.Contains(ip) {
				return true
			}
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil && a == ip {
			return true
		}
	}
	return false
}

func human(n float64) string {
	units := []string{"B", "KB", "MB", "GB"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", n, units[i])
}

// ---------------- port scan / network sweep ----------------

type scanState struct {
	start time.Time
	ports map[netip.Addr]map[uint16]struct{} // per target host: ports tried
	hosts map[uint16]map[netip.Addr]struct{} // per port: hosts tried
}

// PortScanDetector spots one source probing many ports (scan) or many hosts (sweep).
// It looks only at TCP connection attempts (SYN without ACK).
type PortScanDetector struct {
	mu   sync.Mutex
	cfg  func() *Config
	emit func(Alert)
	self netip.Addr
	src  map[netip.Addr]*scanState
}

func NewPortScanDetector(cfg func() *Config, emit func(Alert), self netip.Addr) *PortScanDetector {
	return &PortScanDetector{cfg: cfg, emit: emit, self: self, src: map[netip.Addr]*scanState{}}
}

func (d *PortScanDetector) Observe(p capture.Packet) { d.ObserveAt(p, time.Now()) }

func (d *PortScanDetector) ObserveAt(p capture.Packet, now time.Time) {
	if !p.IP || p.Proto != capture.ProtoTCP || p.TCPFlags&0x12 != 0x02 {
		return
	}
	r := d.cfg().Rules.PortScan
	if !r.Enabled || (r.IgnoreSelf && p.Src == d.self) {
		return
	}
	if len(r.IgnoreSources) > 0 && ipListContains(r.IgnoreSources, p.Src) {
		return
	}
	window := time.Duration(r.WindowSeconds) * time.Second

	var out *Alert
	d.mu.Lock()
	st := d.src[p.Src]
	if st == nil || now.Sub(st.start) > window {
		if st == nil && len(d.src) >= 2048 {
			for k, v := range d.src { // forget sources whose window has ended
				if now.Sub(v.start) > window {
					delete(d.src, k)
				}
			}
			if len(d.src) >= 2048 {
				d.mu.Unlock()
				return
			}
		}
		st = &scanState{start: now, ports: map[netip.Addr]map[uint16]struct{}{},
			hosts: map[uint16]map[netip.Addr]struct{}{}}
		d.src[p.Src] = st
	}

	// one host, many ports
	ps := st.ports[p.Dst]
	if ps == nil && len(st.ports) < 64 {
		ps = map[uint16]struct{}{}
		st.ports[p.Dst] = ps
	}
	if ps != nil {
		ps[p.DstPort] = struct{}{}
		if len(ps) >= r.PortThreshold {
			out = &Alert{Rule: "port_scan", Key: p.Src.String(), IP: p.Src.String(),
				Message: fmt.Sprintf("Port scan detected: %s probed %d ports on %s within %d seconds (ports such as %s)",
					p.Src, len(ps), p.Dst, r.WindowSeconds, samplePorts(ps))}
			delete(d.src, p.Src)
		}
	}

	// one port, many hosts
	if out == nil {
		hs := st.hosts[p.DstPort]
		if hs == nil && len(st.hosts) < 64 {
			hs = map[netip.Addr]struct{}{}
			st.hosts[p.DstPort] = hs
		}
		if hs != nil {
			hs[p.Dst] = struct{}{}
			if len(hs) >= r.HostThreshold {
				out = &Alert{Rule: "port_scan", Key: p.Src.String(), IP: p.Src.String(),
					Message: fmt.Sprintf("Network sweep detected: %s tried port %d on %d different hosts within %d seconds",
						p.Src, p.DstPort, len(hs), r.WindowSeconds)}
				delete(d.src, p.Src)
			}
		}
	}
	d.mu.Unlock()

	if out != nil {
		d.emit(*out) // outside the lock: this may write to the database
	}
}

// ---------------- ARP spoofing ----------------

type arpEntry struct {
	mac [6]byte
	at  time.Time
}

// ARPDetector reports two different hardware addresses claiming one IP address
// within a short time, the classic sign of ARP spoofing.
type ARPDetector struct {
	mu   sync.Mutex
	cfg  func() *Config
	emit func(Alert)
	seen map[netip.Addr]arpEntry
}

func NewARPDetector(cfg func() *Config, emit func(Alert)) *ARPDetector {
	return &ARPDetector{cfg: cfg, emit: emit, seen: map[netip.Addr]arpEntry{}}
}

func (d *ARPDetector) Observe(p capture.Packet) { d.ObserveAt(p, time.Now()) }

func macString(m [6]byte) string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (d *ARPDetector) ObserveAt(p capture.Packet, now time.Time) {
	if !p.ARP || (p.ARPOp != 1 && p.ARPOp != 2) || !p.Src.IsValid() || p.Src.IsUnspecified() {
		return
	}
	if p.ARPMAC == [6]byte{} || p.ARPMAC[0]&1 == 1 { // empty, broadcast or multicast sender
		return
	}
	r := d.cfg().Rules.ARPSpoof
	if !r.Enabled {
		return
	}
	var out *Alert
	d.mu.Lock()
	old, ok := d.seen[p.Src]
	if ok && old.mac != p.ARPMAC && now.Sub(old.at) <= time.Duration(r.ConflictSeconds)*time.Second {
		out = &Alert{Rule: "arp_spoofing", Key: p.Src.String(), IP: p.Src.String(),
			Message: fmt.Sprintf("ARP conflict: %s is claimed by two different devices (%s and %s) within %d seconds. "+
				"This can mean ARP spoofing (a man-in-the-middle attack) or two devices with the same address.",
				p.Src, macString(old.mac), macString(p.ARPMAC), r.ConflictSeconds)}
	}
	if !ok && len(d.seen) >= 4096 {
		for k, v := range d.seen {
			if now.Sub(v.at) > time.Hour {
				delete(d.seen, k)
			}
		}
	}
	if ok || len(d.seen) < 4096 {
		d.seen[p.Src] = arpEntry{mac: p.ARPMAC, at: now}
	}
	d.mu.Unlock()

	if out != nil {
		d.emit(*out)
	}
}

// ---------------- unusual bandwidth ----------------

// MinuteUsage is how much one device moved in the last minute.
type MinuteUsage struct {
	IP         string
	Sent, Recv uint64
}

type bwState struct {
	base float64 // usual bytes per minute (moving average)
	n    int     // minutes observed
}

// BandwidthDetector compares each device's minute to its own usual level.
type BandwidthDetector struct {
	mu   sync.Mutex
	cfg  func() *Config
	emit func(Alert)
	st   map[string]*bwState
}

func NewBandwidthDetector(cfg func() *Config, emit func(Alert)) *BandwidthDetector {
	return &BandwidthDetector{cfg: cfg, emit: emit, st: map[string]*bwState{}}
}

func bwAlert(ip string, sent, recv uint64, base float64) Alert {
	total := float64(sent + recv)
	usual := "not known yet"
	if base > 0 {
		usual = "about " + human(base)
	}
	return Alert{Rule: "bandwidth_spike", Key: ip, IP: ip,
		Message: fmt.Sprintf("Unusual traffic: %s moved %s in the last minute (normally %s): sent %s, received %s",
			ip, human(total), usual, human(float64(sent)), human(float64(recv)))}
}

// Minute is called once a minute with every device's traffic of that minute.
func (d *BandwidthDetector) Minute(usage []MinuteUsage) {
	r := d.cfg().Rules.Bandwidth
	if !r.Enabled {
		return
	}
	var out []Alert
	d.mu.Lock()
	for _, u := range usage {
		s := d.st[u.IP]
		if s == nil {
			if len(d.st) >= 4096 {
				continue
			}
			s = &bwState{}
			d.st[u.IP] = s
		}
		delta := float64(u.Sent + u.Recv)
		limit := math.Max(float64(r.MinMBPerMinute)*1024*1024, r.Factor*s.base)
		if s.n >= r.WarmupMinutes && delta > limit {
			out = append(out, bwAlert(u.IP, u.Sent, u.Recv, s.base))
			// the spike is not added to the "usual" level
		} else if s.n == 0 {
			s.base = delta
		} else {
			s.base = 0.9*s.base + 0.1*delta
		}
		s.n++
	}
	d.mu.Unlock()
	for _, a := range out {
		d.emit(a)
	}
}

// Demo raises a spike alert straight away (used by the demo tools only).
func (d *BandwidthDetector) Demo(ip string, sent, recv uint64) {
	d.emit(bwAlert(ip, sent, recv, 0))
}
