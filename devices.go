package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"homesiem/discovery"
	"homesiem/rules"
	"homesiem/store"
)

// Discovery runs network scans on a timer and records what it finds.
type Discovery struct {
	st       *store.Store
	hub      *Hub
	netw     *discovery.Network
	workers  int
	interval time.Duration
	trigger  chan struct{}
	scanning atomic.Bool
	alerts   *Alerts
}

func NewDiscovery(st *store.Store, hub *Hub, n *discovery.Network, workers int, interval time.Duration, am *Alerts) *Discovery {
	return &Discovery{st: st, hub: hub, netw: n, workers: workers, interval: interval,
		trigger: make(chan struct{}, 1), alerts: am}
}

// Run scans immediately, then every interval, or when Trigger is called.
func (d *Discovery) Run() {
	d.scan()
	t := time.NewTicker(d.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			d.scan()
		case <-d.trigger:
			d.scan()
		}
	}
}

// Trigger asks for an immediate scan (never blocks).
func (d *Discovery) Trigger() {
	select {
	case d.trigger <- struct{}{}:
	default:
	}
}

func describe(ip, name, vendor string) string {
	var parts []string
	if name != "" {
		parts = append(parts, name)
	}
	if vendor != "" {
		parts = append(parts, vendor)
	}
	if len(parts) == 0 {
		return ip
	}
	return ip + " (" + strings.Join(parts, ", ") + ")"
}

// resolveNames looks up hostnames for devices that don't have one yet,
// using the same number of parallel workers as the scan.
func (d *Discovery) resolveNames(hosts []discovery.Host, existing map[string]store.Device) map[string]string {
	names := map[string]string{}
	var mu sync.Mutex
	jobs := make(chan discovery.Host)
	var wg sync.WaitGroup
	for i := 0; i < d.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				name := ""
				if h.Self {
					name, _ = os.Hostname()
				} else {
					name = discovery.ResolveName(h.IP)
				}
				if name != "" {
					mu.Lock()
					names[h.MAC] = name
					mu.Unlock()
				}
			}
		}()
	}
	for _, h := range hosts {
		if existing[h.MAC].Hostname == "" {
			jobs <- h
		}
	}
	close(jobs)
	wg.Wait()
	return names
}

func (d *Discovery) scan() {
	if !d.scanning.CompareAndSwap(false, true) {
		return
	}
	defer d.scanning.Store(false)

	start := time.Now()
	d.hub.BroadcastJSON(map[string]any{"type": "scan", "state": "start"})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	hosts := d.netw.Scan(ctx, d.workers)

	existing := map[string]store.Device{}
	if list, err := d.st.ListDevices(); err == nil {
		for _, dv := range list {
			existing[dv.MAC] = dv
		}
	}
	baseline := len(existing) == 0

	// If the very first scan sees only this machine, the ARP table was
	// probably unreadable. Don't store a bogus baseline.
	if baseline && len(hosts) <= 1 {
		emit(d.st, d.hub, "discovery", "warn",
			"Scan found no other devices. Check you are on the right network (-iface) and that Wi-Fi client isolation is off.")
		d.hub.BroadcastJSON(map[string]any{"type": "scan", "state": "done", "found": len(hosts), "new": 0,
			"ms": time.Since(start).Milliseconds()})
		return
	}

	names := d.resolveNames(hosts, existing)
	now := time.Now().Unix()
	newDevices := 0
	for _, h := range hosts {
		vendor := discovery.Vendor(h.MAC)
		isNew, err := d.st.UpsertDevice(h.MAC, h.IP, names[h.MAC], vendor, now)
		if err != nil {
			log.Printf("store device %s: %v", h.MAC, err)
			continue
		}
		if isNew && !baseline {
			newDevices++
			msg := fmt.Sprintf("New device joined the network: %s [%s]", describe(h.IP, names[h.MAC], vendor), h.MAC)
			d.alerts.Fire(rules.Alert{Rule: "new_device", Key: h.MAC, IP: h.IP, MAC: h.MAC, Message: msg})
		}
	}
	if baseline {
		emit(d.st, d.hub, "discovery", "info", fmt.Sprintf(
			"First scan complete: %d devices learned as the baseline. Devices that join later will raise alerts.", len(hosts)))
	}
	d.hub.BroadcastJSON(map[string]any{"type": "scan", "state": "done", "found": len(hosts),
		"new": newDevices, "ms": time.Since(start).Milliseconds()})
	d.hub.BroadcastJSON(map[string]any{"type": "devices"})
}

// ---------- HTTP API ----------

// postOnly allows only POST requests that carry our custom header. Browsers
// won't send that header from other websites, which blocks drive-by requests.
func postOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-Requested-With") != "homesiem" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func registerAPI(mux *http.ServeMux, st *store.Store, d *Discovery, window int64, ac *Access) {
	mux.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		devs, err := st.ListDevices()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		selfMAC, network, scanning := "", "", false
		if d != nil {
			selfMAC, network, scanning = d.netw.MAC, d.netw.String(), d.scanning.Load()
		}
		now := time.Now().Unix()
		for i := range devs {
			devs[i].Online = now-devs[i].LastSeen <= window
			devs[i].Self = selfMAC != "" && devs[i].MAC == selfMAC
			if why := ac.ProtectedWhy(devs[i], requesterIP(r)); why != "" {
				devs[i].Protected, devs[i].ProtectedWhy = true, why
			}
		}
		sort.Slice(devs, func(i, j int) bool {
			return discovery.IPKey(devs[i].IP) < discovery.IPKey(devs[j].IP)
		})
		writeJSON(w, map[string]any{"now": now, "network": network, "scanning": scanning, "devices": devs})
	})

	mux.HandleFunc("/api/scan", postOnly(func(w http.ResponseWriter, r *http.Request) {
		if d == nil {
			http.Error(w, "device discovery is not running", http.StatusServiceUnavailable)
			return
		}
		d.Trigger()
		w.WriteHeader(http.StatusAccepted)
	}))

	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		alerts, err := st.ListAlerts(limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"alerts": alerts})
	})

	mux.HandleFunc("/api/alerts/ack", postOnly(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		var err error
		if id == "all" {
			err = st.AckAllAlerts()
		} else if n, perr := strconv.ParseInt(id, 10, 64); perr == nil {
			err = st.AckAlert(n)
		} else {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}
