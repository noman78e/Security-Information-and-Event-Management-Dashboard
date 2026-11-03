package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"homesiem/discovery"
	"homesiem/portscan"
	"homesiem/rules"
	"homesiem/store"
)

// riskyWhy explains why a port is risky. Which ports count as risky is set in
// rules.yaml (risky_port.ports); this list only provides the wording.
var riskyWhy = map[int]string{
	21:    "FTP (unencrypted file transfer)",
	23:    "Telnet (unencrypted remote login)",
	2323:  "Telnet (unencrypted remote login)",
	513:   "rlogin (unencrypted remote login)",
	514:   "rsh (unencrypted remote shell)",
	3389:  "Remote Desktop",
	5555:  "Android Debug Bridge",
	5900:  "VNC remote screen",
	7547:  "TR-069 router management",
	37777: "DVR / camera management",
}

type portReq struct{ mac string } // "" = every online device

// PortScanner scans devices for open ports on a schedule or on request.
type PortScanner struct {
	st       *store.Store
	hub      *Hub
	workers  int // devices scanned at the same time
	opts     portscan.Options
	interval time.Duration // automatic rescan interval, 0 = manual only
	window   int64         // a device counts as online if seen within this many seconds
	req      chan portReq
	running  atomic.Bool
	alerts   *Alerts
}

func NewPortScanner(st *store.Store, hub *Hub, workers, conc, ratePerSec int, interval time.Duration, window int64, am *Alerts) *PortScanner {
	if workers < 1 {
		workers = 20
	}
	return &PortScanner{
		st: st, hub: hub, workers: workers, interval: interval, window: window,
		opts: portscan.Options{Timeout: 500 * time.Millisecond, Conc: conc, Limiter: portscan.NewLimiter(ratePerSec)},
		req:  make(chan portReq, 8),
		alerts: am,
	}
}

// Request queues a scan of one device (by MAC) or of all online devices ("").
// It returns false if the queue is full.
func (p *PortScanner) Request(mac string) bool {
	select {
	case p.req <- portReq{mac: mac}:
		return true
	default:
		return false
	}
}

func (p *PortScanner) Run() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	first := time.After(15 * time.Second) // give the first network scan time to finish
	for {
		select {
		case <-first:
			p.auto()
		case <-tick.C:
			p.auto()
		case r := <-p.req:
			p.manual(r)
		}
	}
}

// auto scans online devices that were never scanned or are due again.
func (p *PortScanner) auto() {
	if p.interval <= 0 {
		return
	}
	devs, err := p.st.ListDevices()
	if err != nil {
		log.Printf("port scan: %v", err)
		return
	}
	now := time.Now().Unix()
	var due []store.Device
	for _, d := range devs {
		if d.IP == "" || now-d.LastSeen > p.window {
			continue
		}
		if d.LastPortScan == 0 || now-d.LastPortScan >= int64(p.interval.Seconds()) {
			due = append(due, d)
		}
	}
	if len(due) > 0 {
		p.scanBatch(due)
	}
}

func (p *PortScanner) manual(r portReq) {
	devs, err := p.st.ListDevices()
	if err != nil {
		log.Printf("port scan: %v", err)
		return
	}
	now := time.Now().Unix()
	var pick []store.Device
	for _, d := range devs {
		if d.IP == "" {
			continue
		}
		if r.mac == "" {
			if now-d.LastSeen <= p.window {
				pick = append(pick, d)
			}
		} else if d.MAC == r.mac {
			pick = append(pick, d)
		}
	}
	if len(pick) > 0 {
		p.scanBatch(pick)
	}
}

// scanBatch scans the given devices, up to p.workers of them at a time.
func (p *PortScanner) scanBatch(devs []store.Device) {
	p.running.Store(true)
	defer p.running.Store(false)

	start := time.Now()
	total := len(devs)
	p.hub.BroadcastJSON(map[string]any{"type": "portscan", "state": "start", "total": total})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	jobs := make(chan store.Device)
	var wg sync.WaitGroup
	var done, openTotal atomic.Int64
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				n := p.scanDevice(ctx, d)
				openTotal.Add(int64(n))
				p.hub.BroadcastJSON(map[string]any{"type": "portscan", "state": "progress",
					"done": done.Add(1), "total": total})
			}
		}()
	}
	for _, d := range devs {
		jobs <- d
	}
	close(jobs)
	wg.Wait()

	emit(p.st, p.hub, "portscan", "info", fmt.Sprintf("Port scan finished: %d devices, %d open ports, %.1fs",
		total, openTotal.Load(), time.Since(start).Seconds()))
	p.hub.BroadcastJSON(map[string]any{"type": "portscan", "state": "done", "total": total,
		"open": openTotal.Load(), "ms": time.Since(start).Milliseconds()})
	p.hub.BroadcastJSON(map[string]any{"type": "devices"})
}

// scanDevice scans one device and records the result. It returns the number
// of open ports found.
func (p *PortScanner) scanDevice(ctx context.Context, d store.Device) int {
	scanStart := time.Now().Unix()
	results := portscan.ScanHost(ctx, d.IP, portscan.DefaultPorts, p.opts)
	if ctx.Err() != nil {
		return len(results) // cancelled: don't touch the stored data
	}
	first := d.LastPortScan == 0
	label := describe(d.IP, d.Hostname, d.Vendor)

	for _, r := range results {
		isNew, err := p.st.UpsertPort(d.MAC, r.Port, r.Service, r.Banner, time.Now().Unix())
		if err != nil {
			log.Printf("store port %s:%d: %v", d.MAC, r.Port, err)
			continue
		}
		if !isNew {
			continue
		}
		svc := r.Service
		if svc == "" {
			svc = "unknown service"
		}
		cfg := p.alerts.Config()
		if cfg.Rules.RiskyPort.Enabled && cfg.IsRiskyPort(r.Port) {
			why := riskyWhy[r.Port]
			if why == "" {
				why = svc
			}
			p.alerts.Fire(rules.Alert{Rule: "risky_port", Key: d.MAC + ":" + strconv.Itoa(r.Port), IP: d.IP, MAC: d.MAC,
				Message: fmt.Sprintf("Risky service on %s: %s, port %d/tcp is open", label, why, r.Port)})
		} else if !first {
			p.alerts.Fire(rules.Alert{Rule: "new_open_port", Key: d.MAC + ":" + strconv.Itoa(r.Port), IP: d.IP, MAC: d.MAC,
				Message: fmt.Sprintf("New open port on %s: %d/tcp (%s)", label, r.Port, svc)})
		}
	}

	// Ports that were open before but did not answer this time are closed now.
	// If the device answered nothing at all, the scan is inconclusive (it may
	// be asleep or firewalled), so old results are kept.
	if len(results) > 0 || d.OpenPorts == 0 {
		closed, err := p.st.PruneClosedPorts(d.MAC, scanStart)
		if err != nil {
			log.Printf("prune ports %s: %v", d.MAC, err)
		}
		for _, c := range closed {
			emit(p.st, p.hub, "portscan", "info", fmt.Sprintf("Port %d/tcp is now closed on %s", c.Port, label))
		}
	}
	if err := p.st.SetPortScanned(d.MAC, time.Now().Unix()); err != nil {
		log.Printf("mark scanned %s: %v", d.MAC, err)
	}
	return len(results)
}

// ---------- HTTP API ----------

func registerPortAPI(mux *http.ServeMux, st *store.Store, ps *PortScanner) {
	// GET /api/ports?mac=AA:BB:CC:DD:EE:FF  -> open ports of one device
	mux.HandleFunc("/api/ports", func(w http.ResponseWriter, r *http.Request) {
		mac := discovery.NormMAC(r.URL.Query().Get("mac"))
		if mac == "" {
			http.Error(w, "bad mac", http.StatusBadRequest)
			return
		}
		ports, err := st.ListPorts(mac)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"mac": mac, "ports": ports})
	})

	// POST /api/portscan?mac=all   or   ?mac=AA:BB:CC:DD:EE:FF
	// Only devices already known from discovery can be scanned. The API never
	// accepts an arbitrary IP address.
	mux.HandleFunc("/api/portscan", postOnly(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("mac")
		mac := ""
		if q != "" && q != "all" {
			mac = discovery.NormMAC(q)
			if mac == "" {
				http.Error(w, "bad mac", http.StatusBadRequest)
				return
			}
		}
		if !ps.Request(mac) {
			http.Error(w, "port scanner is busy, try again shortly", http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
}
