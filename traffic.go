package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"time"

	"homesiem/capture"
	"homesiem/discovery"
	"homesiem/portscan"
	"homesiem/rules"
	"homesiem/store"
)

type TrafficConfig struct {
	Mode       string // auto | off | demo
	Iface      string
	Promisc    bool
	FlushEvery time.Duration
	MaxRows    int
	MaxFlows   int
}

// Traffic runs packet capture (or the demo generator), summarizes it into
// flows, pushes live numbers to the dashboard and saves flows to SQLite.
type Traffic struct {
	st      *store.Store
	hub     *Hub
	cfg     TrafficConfig
	agg     *capture.Aggregator
	local   *net.IPNet
	iface   string
	started time.Time
	src     capture.Source

	am   *Alerts
	scan *rules.PortScanDetector
	arp  *rules.ARPDetector
	bw   *rules.BandwidthDetector
	dest *DestTracker
	self netip.Addr
	prev map[string][2]uint64 // per-device totals at the last minute mark (run goroutine only)

	mu   sync.Mutex
	mode string // live | demo | off
	note string
}

func NewTraffic(st *store.Store, hub *Hub, cfg TrafficConfig, netw *discovery.Network, am *Alerts) *Traffic {
	local := &net.IPNet{IP: net.IPv4(192, 168, 1, 0).To4(), Mask: net.CIDRMask(24, 32)}
	iface := cfg.Iface
	if netw != nil {
		local = netw.IPNet
		if iface == "" {
			iface = netw.IfaceName
		}
	}
	t := &Traffic{st: st, hub: hub, cfg: cfg, local: local, iface: iface, started: time.Now(),
		agg: capture.NewAggregator(local, cfg.MaxFlows), am: am, prev: map[string][2]uint64{}}

	// The detectors. They report through the alert manager, which applies rules.yaml.
	if netw != nil {
		if a, ok := netip.AddrFromSlice(netw.IP.To4()); ok {
			t.self = a
		}
	}
	fire := func(a rules.Alert) { am.Fire(a) }
	t.scan = rules.NewPortScanDetector(am.Config, fire, t.self)
	t.arp = rules.NewARPDetector(am.Config, fire)
	t.bw = rules.NewBandwidthDetector(am.Config, fire)
	t.dest = NewDestTracker(st, am)

	switch cfg.Mode {
	case "off":
		t.setStatus("off", "Capture was turned off with -capture off.")
	case "demo":
		t.setStatus("demo", "Simulated traffic for previewing the dashboard. Nothing shown here is real.")
	default: // auto
		if runtime.GOOS != "linux" {
			t.setStatus("off", "Live capture works on Linux (Raspberry Pi or a Linux PC) in this version. "+
				"Start with -capture demo to preview this page with simulated traffic.")
		} else if iface == "" {
			t.setStatus("off", "No network interface found to capture on. Use -capture-iface.")
		} else if src, err := capture.Open(iface, cfg.Promisc); err != nil {
			t.setStatus("off", fmt.Sprintf("Could not start capture on %s: %v. On Linux run as root, or give the "+
				"program the capability: sudo setcap cap_net_raw,cap_net_admin+ep ./homesiem", iface, err))
		} else {
			t.src = src
			t.setStatus("live", "Only packet headers are inspected. Payloads are never stored.")
		}
	}
	return t
}

func (t *Traffic) setStatus(mode, note string) {
	t.mu.Lock()
	t.mode, t.note = mode, note
	t.mu.Unlock()
}

func (t *Traffic) status() (string, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.mode, t.note
}

// Close stops capturing and restores the network card settings.
func (t *Traffic) Close() {
	if t.src != nil {
		t.src.Close()
	}
}

// Start launches the background workers.
func (t *Traffic) Start() {
	mode, note := t.status()
	emit(t.st, t.hub, "traffic", "info", fmt.Sprintf("Traffic monitor %s. %s", mode, note))
	switch mode {
	case "live":
		log.Printf("traffic: capturing on %s, saving flows every %s", t.iface, t.cfg.FlushEvery)
		go t.captureLoop()
	case "demo":
		log.Printf("traffic: DEMO mode (simulated traffic)")
		go t.demoLoop()
	default:
		log.Printf("traffic: capture off (%s)", note)
		return
	}
	go t.run()
}

func (t *Traffic) captureLoop() {
	buf := make([]byte, 256) // headers only
	failures := 0
	for {
		n, wire, err := t.src.Read(buf)
		if err != nil {
			failures++
			if failures > 20 {
				t.setStatus("off", "Capture stopped: "+err.Error())
				emit(t.st, t.hub, "traffic", "error", "Packet capture stopped: "+err.Error())
				return
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		failures = 0
		if n == 0 {
			continue
		}
		p := capture.Parse(buf[:n])
		t.agg.Add(p, wire)
		if p.ARP {
			t.arp.Observe(p)
		} else {
			t.scan.Observe(p)
		}
	}
}

// run pushes live numbers every second and saves flows on a timer.
func (t *Traffic) run() {
	sec := time.NewTicker(time.Second)
	flush := time.NewTicker(t.cfg.FlushEvery)
	minute := time.NewTicker(time.Minute)
	defer sec.Stop()
	defer flush.Stop()
	defer minute.Stop()
	for {
		select {
		case <-sec.C:
			s := t.agg.Tick()
			if t.hub.ClientCount() == 0 {
				continue // no dashboard is open
			}
			mode, _ := t.status()
			t.hub.BroadcastJSON(map[string]any{"type": "traffic", "mode": mode,
				"down": s.Down, "up": s.Up, "lan": s.Lan, "other": s.Other, "pps": s.Packets})
		case <-flush.C:
			t.flush()
		case <-minute.C:
			t.minuteCheck()
		}
	}
}

func (t *Traffic) flush() {
	all := t.agg.FlushRaw()
	if len(all) == 0 {
		return
	}
	t.dest.OnFlows(all) // the rules see every flow, even the ones trimmed below
	rows := capture.TrimRows(all, t.cfg.MaxRows)
	out := make([]store.FlowRow, len(rows))
	for i, r := range rows {
		out[i] = store.FlowRow{Src: r.Src, Dst: r.Dst, Port: r.Port, Proto: r.Proto, Dir: r.Dir,
			Bytes: int64(r.Bytes), Packets: int64(r.Packets)}
	}
	if err := t.st.AddFlows(time.Now().Unix(), out); err != nil {
		log.Printf("store flows: %v", err)
	}
}

// minuteCheck works out how much each device moved during the last minute.
func (t *Traffic) minuteCheck() {
	snap := t.agg.Snapshot()
	cur := make(map[string][2]uint64, len(snap.Talkers))
	var usage []rules.MinuteUsage
	for _, tk := range snap.Talkers {
		cur[tk.IP] = [2]uint64{tk.Sent, tk.Recv}
		if prev, ok := t.prev[tk.IP]; ok {
			usage = append(usage, rules.MinuteUsage{IP: tk.IP, Sent: tk.Sent - prev[0], Recv: tk.Recv - prev[1]})
		}
	}
	t.prev = cur
	t.bw.Minute(usage)
}

// DemoAttack feeds a fake attack through the real detectors (only in demo mode),
// so you can see alerts, notifications and the Alerts page without a real network.
func (t *Traffic) DemoAttack(kind string) error {
	if mode, _ := t.status(); mode != "demo" {
		return fmt.Errorf("the demo tools only work when started with -capture demo")
	}
	base := [4]byte{192, 168, 1, 0}
	if b := t.local.IP.To4(); b != nil {
		base = [4]byte{b[0], b[1], b[2], 0}
	}
	target := t.demoLocals()[0]
	attacker := netip.AddrFrom4(randomLANAddr(base, 200, 249)) // a new made-up address each click
	switch kind {
	case "portscan":
		for port := 1; port <= 40; port++ {
			t.scan.Observe(capture.Packet{IP: true, Src: attacker, Dst: target, SrcPort: 50000,
				DstPort: uint16(port), Proto: capture.ProtoTCP, TCPFlags: 0x02})
		}
	case "spike":
		t.bw.Demo(attacker.String(), 90<<20, 40<<20)
	case "arp":
		victim := netip.AddrFrom4(randomLANAddr(base, 100, 149))
		t.arp.Observe(capture.Packet{ARP: true, ARPOp: 2, Src: victim, ARPMAC: [6]byte{2, 0xaa, 0xbb, 0xcc, 0xdd, 1}})
		t.arp.Observe(capture.Packet{ARP: true, ARPOp: 2, Src: victim, ARPMAC: [6]byte{2, 0xaa, 0xbb, 0xcc, 0xdd, 2}})
	default:
		return fmt.Errorf("unknown demo attack %q", kind)
	}
	return nil
}

// ---------- demo mode ----------

func (t *Traffic) demoLocals() []netip.Addr {
	var out []netip.Addr
	if devs, err := t.st.ListDevices(); err == nil {
		for _, d := range devs {
			if a, err := netip.ParseAddr(d.IP); err == nil && a.Is4() {
				out = append(out, a)
			}
		}
	}
	if len(out) == 0 {
		b := t.local.IP.To4()
		for i := byte(10); i < 13; i++ {
			out = append(out, netip.AddrFrom4([4]byte{b[0], b[1], b[2], i}))
		}
	}
	return out
}

// demoLoop invents traffic between your real devices and addresses from the
// reserved documentation ranges (they never belong to real servers).
func (t *Traffic) demoLoop() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	remotes := []netip.Addr{
		netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.77"),
		netip.MustParseAddr("198.51.100.5"), netip.MustParseAddr("198.51.100.200"),
		netip.MustParseAddr("192.0.2.44"),
	}
	ports := []uint16{443, 443, 443, 443, 80, 53, 123, 8883}
	var locals []netip.Addr
	for tick := 0; ; tick++ {
		if tick%20 == 0 {
			locals = t.demoLocals()
		}
		n := 20 + rng.Intn(80)
		for i := 0; i < n; i++ {
			l := locals[rng.Intn(len(locals))]
			if rng.Intn(2) == 0 {
				l = locals[0] // one chatty device
			}
			r := remotes[rng.Intn(len(remotes))]
			port := ports[rng.Intn(len(ports))]
			eph := uint16(40000 + rng.Intn(20000))
			if rng.Intn(4) == 0 {
				t.agg.Add(capture.Packet{IP: true, Src: l, Dst: r, SrcPort: eph, DstPort: port, Proto: capture.ProtoTCP}, 60+rng.Intn(400))
			} else {
				t.agg.Add(capture.Packet{IP: true, Src: r, Dst: l, SrcPort: port, DstPort: eph, Proto: capture.ProtoTCP}, 1000+rng.Intn(500))
			}
		}
		time.Sleep(time.Second)
	}
}

// ---------- HTTP API ----------

func registerTrafficAPI(mux *http.ServeMux, st *store.Store, tr *Traffic) {
	mux.HandleFunc("/api/traffic", func(w http.ResponseWriter, r *http.Request) {
		mode, note := tr.status()
		snap := tr.agg.Snapshot()

		byIP := map[string]store.Device{}
		if devs, err := st.ListDevices(); err == nil {
			for _, d := range devs {
				byIP[d.IP] = d
			}
		}
		type talkerOut struct {
			IP       string `json:"ip"`
			Name     string `json:"name"`
			MAC      string `json:"mac"`
			Sent     uint64 `json:"sent"`
			Recv     uint64 `json:"recv"`
			SentRate uint64 `json:"sentRate"`
			RecvRate uint64 `json:"recvRate"`
		}
		sort.Slice(snap.Talkers, func(i, j int) bool {
			return snap.Talkers[i].Sent+snap.Talkers[i].Recv > snap.Talkers[j].Sent+snap.Talkers[j].Recv
		})
		if len(snap.Talkers) > 20 {
			snap.Talkers = snap.Talkers[:20]
		}
		talkers := make([]talkerOut, 0, len(snap.Talkers))
		for _, t := range snap.Talkers {
			o := talkerOut{IP: t.IP, Sent: t.Sent, Recv: t.Recv, SentRate: t.SentRate, RecvRate: t.RecvRate}
			if d, ok := byIP[t.IP]; ok {
				o.MAC = d.MAC
				o.Name = d.Hostname
				if o.Name == "" {
					o.Name = d.Vendor
				}
			}
			talkers = append(talkers, o)
		}

		now := time.Now().Unix()
		remote, err := st.TopRemote(now-600, 15)
		if err != nil {
			remote = []store.RemoteHost{}
		}
		for i := range remote {
			remote[i].Service = portscan.ServiceName(remote[i].Port)
		}

		writeJSON(w, map[string]any{
			"mode": mode, "iface": tr.iface, "note": note, "now": now, "since": tr.started.Unix(),
			"totals": map[string]uint64{"down": snap.Total.Down, "up": snap.Total.Up, "lan": snap.Total.Lan,
				"other": snap.Total.Other, "packets": snap.Total.Packets},
			"dropped": snap.Dropped,
			"talkers": talkers,
			"remote":  remote,
		})
	})
}
