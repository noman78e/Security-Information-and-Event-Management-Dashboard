package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"homesiem/discovery"
	"homesiem/fw"
	"homesiem/store"
)

// Access decides which devices are blocked or slowed down and keeps the
// firewall in step with that decision.
//
// Modes:
//
//	enforcing  the rules are loaded into the Linux firewall (nftables)
//	dry-run    the rules are worked out and shown, but nothing is changed
//	off         the feature is disabled
//
// Blocking works only for traffic that passes through THIS computer, so it
// must be your network's gateway.
type Access struct {
	st   *store.Store
	hub  *Hub
	mode string
	why  string // why the mode is not "enforcing", for the dashboard

	selfMAC, selfIP, gwIP string

	mu          sync.Mutex
	script      string
	lastApplied int64
	lastErr     string
	macMatch    bool // false = MAC matching was refused by nft, IPv4 addresses are used instead
}

func NewAccess(st *store.Store, hub *Hub, flagMode string, netw *discovery.Network) *Access {
	a := &Access{st: st, hub: hub, macMatch: true}
	if netw != nil {
		a.selfMAC, a.selfIP = netw.MAC, netw.IP.String()
		a.gwIP = fw.DefaultGateway()
		if a.gwIP == "" { // not Linux, or no default route: assume the usual router address
			if b := netw.IP.To4(); b != nil {
				a.gwIP = fmt.Sprintf("%d.%d.%d.1", b[0], b[1], b[2])
			}
		}
	}
	switch {
	case flagMode == "off":
		a.mode, a.why = "off", "Access control was turned off with -enforce off."
	case flagMode == "dry-run":
		a.mode, a.why = "dry-run", "Started with -enforce dry-run: rules are worked out and shown, but nothing on your network is changed."
	case runtime.GOOS != "linux":
		a.mode, a.why = "dry-run", "Blocking needs Linux with nftables, on the computer that is your network's gateway. Rules are worked out and shown, but nothing is changed."
	default:
		if _, err := exec.LookPath("nft"); err != nil {
			a.mode, a.why = "dry-run", "The nft program was not found. Install it with: sudo apt install nftables"
		} else if os.Geteuid() != 0 && !fw.HasNetAdmin() {
			a.mode, a.why = "dry-run", "Changing firewall rules needs administrator rights. Start HomeSIEM with sudo, or as a service with the CAP_NET_ADMIN capability (see the deploy folder)."
		} else {
			a.mode = "enforcing"
		}
	}
	return a
}

// Start restores the saved blocks (firewall rules vanish at reboot) and
// starts the timer that ends temporary blocks.
func (a *Access) Start() {
	if a.mode == "off" {
		return
	}
	a.mu.Lock()
	err := a.applyLocked()
	a.mu.Unlock()
	if err != nil {
		log.Printf("access control: %v", err)
		emit(a.st, a.hub, "access", "error", "Could not restore blocked devices: "+err.Error())
	}
	log.Printf("access control: %s", a.mode)
	go a.expiryLoop()
}

// ProtectedWhy explains why a device must not be blocked, or returns "".
func (a *Access) ProtectedWhy(d store.Device, requester string) string {
	switch {
	case a == nil:
		return ""
	case (a.selfMAC != "" && d.MAC == a.selfMAC) || (a.selfIP != "" && d.IP == a.selfIP):
		return "this is the computer running HomeSIEM"
	case a.gwIP != "" && d.IP == a.gwIP:
		return "this looks like your router"
	case d.Trusted:
		return "you marked it as protected"
	case requester != "" && d.IP == requester:
		return "it is the device you are using right now"
	}
	return ""
}

func (a *Access) find(mac string) (store.Device, error) {
	devs, err := a.st.ListDevices()
	if err != nil {
		return store.Device{}, err
	}
	for _, d := range devs {
		if d.MAC == mac {
			return d, nil
		}
	}
	return store.Device{}, errors.New("unknown device")
}

// applyLocked works out the rules from the database and loads them.
func (a *Access) applyLocked() error {
	devs, err := a.st.ListDevices()
	if err != nil {
		return err
	}
	var entries []fw.Entry
	for _, d := range devs {
		if !d.Blocked && d.LimitKBytes <= 0 {
			continue
		}
		if why := a.ProtectedWhy(d, ""); why != "" {
			log.Printf("access control: ignoring the block of %s (%s)", d.MAC, why)
			continue // never cut off the router, this computer or protected devices
		}
		entries = append(entries, fw.Entry{MAC: d.MAC, IP: d.IP, Block: d.Blocked, LimitKBytes: d.LimitKBytes})
	}

	if len(entries) == 0 {
		if a.mode == "enforcing" {
			if err := fw.Remove(); err != nil {
				a.lastErr = err.Error()
				return err
			}
		}
		a.script = "# Nobody is blocked or speed limited, so no firewall rules are installed.\n"
		a.lastApplied, a.lastErr = time.Now().Unix(), ""
		return nil
	}

	script := fw.Script(entries, a.macMatch)
	if a.mode == "enforcing" {
		if err := fw.Load(script); err != nil {
			// some systems refuse to match hardware addresses: try with IPv4 addresses only
			alt := fw.Script(entries, false)
			if a.macMatch && fw.Load(alt) == nil {
				a.macMatch, script = false, alt
				emit(a.st, a.hub, "access", "warn", "This system cannot match hardware addresses, so devices are blocked by IPv4 address only.")
			} else {
				a.lastErr = err.Error()
				return err
			}
		}
	}
	a.script = script
	a.lastApplied, a.lastErr = time.Now().Unix(), ""
	return nil
}

func (a *Access) changed() {
	a.hub.BroadcastJSON(map[string]any{"type": "devices"})
}

func label(d store.Device) string {
	return describe(d.IP, d.Hostname, d.Vendor)
}

// Block blocks a device. minutes = 0 means until it is unblocked by hand.
func (a *Access) Block(mac, requester string, minutes int, note string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode == "off" {
		return errors.New("access control is turned off")
	}
	d, err := a.find(mac)
	if err != nil {
		return err
	}
	if why := a.ProtectedWhy(d, requester); why != "" {
		return fmt.Errorf("this device cannot be blocked: %s", why)
	}
	var until int64
	if minutes > 0 {
		until = time.Now().Add(time.Duration(minutes) * time.Minute).Unix()
	}
	if err := a.st.SetBlocked(mac, true, until, note); err != nil {
		return err
	}
	if err := a.applyLocked(); err != nil {
		a.st.SetBlocked(mac, d.Blocked, d.BlockedUntil, d.BlockNote) // undo: the dashboard must never show a block that is not real
		return err
	}
	how := "until you unblock it"
	if minutes > 0 {
		how = fmt.Sprintf("for %d minutes", minutes)
	}
	emit(a.st, a.hub, "access", "warn", fmt.Sprintf("Blocked %s [%s] %s (mode: %s)", label(d), d.MAC, how, a.mode))
	a.changed()
	return nil
}

// Unblock lets a device back onto the network.
func (a *Access) Unblock(mac string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := a.find(mac)
	if err != nil {
		return err
	}
	if err := a.st.SetBlocked(mac, false, 0, ""); err != nil {
		return err
	}
	if err := a.applyLocked(); err != nil {
		a.st.SetBlocked(mac, d.Blocked, d.BlockedUntil, d.BlockNote)
		return err
	}
	emit(a.st, a.hub, "access", "info", fmt.Sprintf("Unblocked %s [%s]", label(d), d.MAC))
	a.changed()
	return nil
}

// Limit slows a device down to kbit kilobits per second (0 removes the limit).
func (a *Access) Limit(mac, requester string, kbit int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode == "off" {
		return errors.New("access control is turned off")
	}
	d, err := a.find(mac)
	if err != nil {
		return err
	}
	if kbit > 0 {
		if why := a.ProtectedWhy(d, requester); why != "" {
			return fmt.Errorf("this device cannot be slowed down: %s", why)
		}
	}
	kbytes := kbit / 8
	if kbit > 0 && kbytes < 1 {
		kbytes = 1
	}
	if err := a.st.SetLimit(mac, kbytes); err != nil {
		return err
	}
	if err := a.applyLocked(); err != nil {
		a.st.SetLimit(mac, d.LimitKBytes)
		return err
	}
	if kbytes > 0 {
		emit(a.st, a.hub, "access", "warn", fmt.Sprintf("Speed of %s [%s] limited to %d kbit/s (mode: %s)", label(d), d.MAC, kbytes*8, a.mode))
	} else {
		emit(a.st, a.hub, "access", "info", fmt.Sprintf("Speed limit removed from %s [%s]", label(d), d.MAC))
	}
	a.changed()
	return nil
}

// Protect marks a device as one that can never be blocked. Protecting a blocked device unblocks it.
func (a *Access) Protect(mac string, on bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, err := a.find(mac)
	if err != nil {
		return err
	}
	if err := a.st.SetTrusted(mac, on); err != nil {
		return err
	}
	if on && (d.Blocked || d.LimitKBytes > 0) {
		a.st.SetBlocked(mac, false, 0, "")
		a.st.SetLimit(mac, 0)
		if a.mode != "off" {
			if err := a.applyLocked(); err != nil {
				return err
			}
		}
	}
	emit(a.st, a.hub, "access", "info", fmt.Sprintf("%s [%s] %s", label(d), d.MAC,
		map[bool]string{true: "is now protected from blocking", false: "is no longer protected"}[on]))
	a.changed()
	return nil
}

// ReleaseAll is the panic button: everybody is unblocked and every limit removed.
func (a *Access) ReleaseAll() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.st.ClearAccess(); err != nil {
		return err
	}
	if err := a.applyLocked(); err != nil {
		return err
	}
	emit(a.st, a.hub, "access", "warn", "All blocks and speed limits were removed")
	a.changed()
	return nil
}

func (a *Access) expiryLoop() {
	for range time.Tick(30 * time.Second) {
		macs, err := a.st.ExpiredBlocks(time.Now().Unix())
		if err != nil || len(macs) == 0 {
			continue
		}
		a.mu.Lock()
		for _, m := range macs {
			a.st.SetBlocked(m, false, 0, "")
			emit(a.st, a.hub, "access", "info", "The temporary block on "+m+" ended")
		}
		if err := a.applyLocked(); err != nil {
			log.Printf("access control: %v", err)
		}
		a.mu.Unlock()
		a.changed()
	}
}

// Status describes the access control for the dashboard.
func (a *Access) Status() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	blocked, limited := a.st.AccessCounts()
	return map[string]any{
		"mode": a.mode, "reason": a.why,
		"forwarding": fw.Forwarding(), "gateway": a.gwIP, "self": a.selfIP,
		"macMatching": a.macMatch, "lastApplied": a.lastApplied, "lastError": a.lastErr,
		"blocked": blocked, "limited": limited, "script": a.script,
	}
}

// ---------- HTTP API ----------

func requesterIP(r *http.Request) string {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap().String()
	}
	return ""
}

func registerAccessAPI(mux *http.ServeMux, ac *Access) {
	reply := func(w http.ResponseWriter, err error) {
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	mac := func(r *http.Request) (string, error) {
		m := discovery.NormMAC(r.URL.Query().Get("mac"))
		if m == "" {
			return "", errors.New("bad device address")
		}
		return m, nil
	}
	num := func(r *http.Request, key string, max int) (int, error) {
		v := r.URL.Query().Get(key)
		if v == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > max {
			return 0, fmt.Errorf("bad value for %s", key)
		}
		return n, nil
	}

	mux.HandleFunc("/api/access", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, ac.Status())
	})
	mux.HandleFunc("/api/access/block", postOnly(func(w http.ResponseWriter, r *http.Request) {
		m, err := mac(r)
		if err != nil {
			reply(w, err)
			return
		}
		minutes, err := num(r, "minutes", 7*24*60)
		if err != nil {
			reply(w, err)
			return
		}
		reply(w, ac.Block(m, requesterIP(r), minutes, "blocked from the dashboard"))
	}))
	mux.HandleFunc("/api/access/unblock", postOnly(func(w http.ResponseWriter, r *http.Request) {
		m, err := mac(r)
		if err != nil {
			reply(w, err)
			return
		}
		reply(w, ac.Unblock(m))
	}))
	mux.HandleFunc("/api/access/limit", postOnly(func(w http.ResponseWriter, r *http.Request) {
		m, err := mac(r)
		if err != nil {
			reply(w, err)
			return
		}
		kbit, err := num(r, "kbit", 1000000)
		if err != nil {
			reply(w, err)
			return
		}
		reply(w, ac.Limit(m, requesterIP(r), kbit))
	}))
	mux.HandleFunc("/api/access/protect", postOnly(func(w http.ResponseWriter, r *http.Request) {
		m, err := mac(r)
		if err != nil {
			reply(w, err)
			return
		}
		reply(w, ac.Protect(m, r.URL.Query().Get("on") == "1"))
	}))
	mux.HandleFunc("/api/access/release-all", postOnly(func(w http.ResponseWriter, r *http.Request) {
		reply(w, ac.ReleaseAll())
	}))
}
