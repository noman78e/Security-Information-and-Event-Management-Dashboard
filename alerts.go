package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"homesiem/rules"
	"homesiem/store"
)

// Alerts is the single place where alerts are created. Every detector (new
// device, port scan, ARP spoofing...) calls Fire. Fire looks up the rule in
// rules.yaml and decides whether to keep quiet, which severity to use, and
// whether to send a notification.
type Alerts struct {
	st   *store.Store
	hub  *Hub
	path string

	mu       sync.RWMutex
	cfg      *rules.Config
	notifier *rules.Notifier
	loadedAt time.Time

	coolMu     sync.Mutex
	cool       map[string]time.Time
	suppressed atomic.Uint64

	sentMu    sync.Mutex
	sentCount int
	sentSince time.Time
}

// NewAlerts loads rules.yaml (creating it with the defaults if missing).
// A broken file never stops the program: the built-in defaults are used.
func NewAlerts(st *store.Store, hub *Hub, path string) *Alerts {
	a := &Alerts{st: st, hub: hub, cool: map[string]time.Time{}, sentSince: time.Now()}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	a.path = path
	cfg, warns, err := rules.LoadOrCreate(path)
	if err != nil {
		log.Printf("rules: %v. Using the built-in defaults.", err)
		cfg, warns = rules.Defaults(), nil
		emit(st, hub, "rules", "error", "rules.yaml could not be loaded, built-in defaults are active: "+err.Error())
	}
	for _, w := range warns {
		log.Printf("rules: %s", w)
	}
	a.set(cfg)
	log.Printf("rules loaded from %s", path)
	return a
}

func (a *Alerts) set(cfg *rules.Config) {
	a.mu.Lock()
	a.cfg = cfg
	a.notifier = rules.NewNotifier(cfg.Notify)
	a.loadedAt = time.Now()
	a.mu.Unlock()
}

// Config returns the active rules. Treat it as read-only.
func (a *Alerts) Config() *rules.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

func (a *Alerts) currentNotifier() *rules.Notifier {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.notifier
}

// Reload re-reads rules.yaml. If the file is invalid the old rules stay active.
func (a *Alerts) Reload() error {
	cfg, warns, err := rules.Load(a.path)
	if err != nil {
		emit(a.st, a.hub, "rules", "error", "Reload failed, old rules stay active: "+err.Error())
		return err
	}
	a.set(cfg)
	msg := "Rules reloaded from rules.yaml"
	if len(warns) > 0 {
		msg += " (" + strings.Join(warns, "; ") + ")"
	}
	emit(a.st, a.hub, "rules", "info", msg)
	return nil
}

func (a *Alerts) allow(key string, quiet time.Duration) bool {
	a.coolMu.Lock()
	defer a.coolMu.Unlock()
	now := time.Now()
	if last, ok := a.cool[key]; ok && now.Sub(last) < quiet {
		return false
	}
	if len(a.cool) > 4096 {
		for k, t := range a.cool {
			if now.Sub(t) > time.Hour {
				delete(a.cool, k)
			}
		}
	}
	a.cool[key] = now
	return true
}

func (a *Alerts) macForIP(ip string) string {
	devs, err := a.st.ListDevices()
	if err != nil {
		return ""
	}
	for _, d := range devs {
		if d.IP == ip {
			return d.MAC
		}
	}
	return ""
}

// Fire raises an alert. It returns false if the rule is off or quiet.
func (a *Alerts) Fire(al rules.Alert) bool {
	cfg := a.Config()
	c := cfg.Rules.Lookup(al.Rule)
	if c == nil || !c.Enabled {
		return false
	}
	if c.CooldownMin > 0 && al.Key != "" &&
		!a.allow(al.Rule+"|"+al.Key, time.Duration(c.CooldownMin)*time.Minute) {
		a.suppressed.Add(1)
		return false
	}
	mac := al.MAC
	if mac == "" && al.IP != "" {
		mac = a.macForIP(al.IP)
	}
	sev := c.Severity
	if rules.SeverityRank(al.Severity) > 0 {
		sev = al.Severity // a log rule can set its own severity
	}
	label := al.Rule
	if al.Label != "" {
		label = al.Label
	}
	rec, err := a.st.AddAlert(sev, label, mac, al.Message)
	if err != nil {
		log.Printf("store alert: %v", err)
		return false
	}
	a.hub.BroadcastJSON(map[string]any{"type": "alert", "id": rec.ID})
	level := "warn"
	if sev == "high" {
		level = "error"
	}
	emit(a.st, a.hub, "alerts", level, fmt.Sprintf("[%s] %s", label, al.Message))

	if c.Notify && rules.SeverityRank(sev) >= rules.SeverityRank(cfg.Notify.MinSeverity) {
		al.Rule = label
		go a.notify(sev, al)
	}
	return true
}

// notify sends an alert to the configured channels, at most 30 per hour.
func (a *Alerts) notify(severity string, al rules.Alert) {
	n := a.currentNotifier()
	if n == nil || len(n.Channels()) == 0 {
		return
	}
	a.sentMu.Lock()
	if time.Since(a.sentSince) > time.Hour {
		a.sentSince, a.sentCount = time.Now(), 0
	}
	a.sentCount++
	over := a.sentCount > 30
	a.sentMu.Unlock()
	if over {
		log.Printf("notifications: limit of 30 per hour reached, not sending [%s]", al.Rule)
		return
	}
	title := fmt.Sprintf("HomeSIEM %s alert: %s", strings.ToUpper(severity), al.Rule)
	for ch, err := range n.Send(title, al.Message) {
		if err != nil {
			log.Printf("notification via %s failed: %v", ch, err)
		}
	}
}

// TestNotify sends a test message to every configured channel.
func (a *Alerts) TestNotify() (map[string]string, error) {
	n := a.currentNotifier()
	if n == nil || len(n.Channels()) == 0 {
		return nil, errors.New("no notification channel is configured in rules.yaml (Telegram, webhook or email)")
	}
	out := map[string]string{}
	for ch, err := range n.Send("HomeSIEM test notification", "If you can read this, notifications work.") {
		if err != nil {
			out[ch] = err.Error()
		} else {
			out[ch] = "ok"
		}
	}
	return out, nil
}

// ---------- what the Rules page shows ----------

var ruleText = map[string][2]string{
	"login_lockout":   {"Dashboard lock-out", "Someone entered the dashboard password wrongly too often and was locked out for 15 minutes."},
	"log_match":       {"Log rules", "Messages received from routers and other machines match a pattern in log_rules (for example repeated failed logins)."},
	"new_device":      {"New device", "A device that was not there at the first scan joins the network."},
	"risky_port":      {"Risky service", "A risky service such as Telnet, FTP or remote desktop is found open on a device."},
	"new_open_port":   {"New open port", "A port opens on a device that was already scanned before."},
	"port_scan":       {"Port scan / sweep", "One address probes many ports on one host, or one port on many hosts (like nmap does)."},
	"bandwidth_spike": {"Unusual bandwidth", "A device moves far more data in a minute than it normally does."},
	"new_destination": {"New destination", "A device connects to an outside address and port it has never used before."},
	"arp_spoofing":    {"ARP spoofing", "Two different devices claim the same IP address, a sign of a man-in-the-middle attack."},
}

func joinInts(v []int) string {
	if len(v) == 0 {
		return "none"
	}
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ", ")
}

func ruleParams(name string, c *rules.Config) []string {
	r := c.Rules
	switch name {
	case "risky_port":
		return []string{"ports: " + joinInts(r.RiskyPort.Ports)}
	case "port_scan":
		p := r.PortScan
		return []string{
			fmt.Sprintf("%d ports on one host or %d hosts on one port within %ds", p.PortThreshold, p.HostThreshold, p.WindowSeconds),
			fmt.Sprintf("ignore this computer: %v", p.IgnoreSelf),
			fmt.Sprintf("trusted sources: %d", len(p.IgnoreSources)),
		}
	case "bandwidth_spike":
		b := r.Bandwidth
		return []string{fmt.Sprintf("at least %d MB per minute and %.1f times the usual", b.MinMBPerMinute, b.Factor),
			fmt.Sprintf("learns for %d minutes first", b.WarmupMinutes)}
	case "new_destination":
		d := r.NewDestination
		return []string{fmt.Sprintf("learns for %d hours first", d.LearningHours),
			"ignored ports: " + joinInts(d.IgnorePorts),
			fmt.Sprintf("strict devices: %d", len(d.StrictDevices))}
	case "arp_spoofing":
		return []string{fmt.Sprintf("conflict window: %ds", r.ARPSpoof.ConflictSeconds)}
	case "log_match":
		var out []string
		for _, lr := range c.LogRules {
			out = append(out, fmt.Sprintf("%s (%s, %d in %ds, per %s)", lr.Name, lr.Severity, lr.Threshold, lr.WithinSeconds, lr.GroupBy))
		}
		if len(out) == 0 {
			out = []string{"no patterns in log_rules"}
		}
		return out
	}
	return nil
}

type ruleView struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	Severity    string   `json:"severity"`
	CooldownMin int      `json:"cooldownMinutes"`
	Notify      bool     `json:"notify"`
	Params      []string `json:"params"`
}

// View describes the active rules for the dashboard. It never includes secrets.
func (a *Alerts) View() map[string]any {
	cfg := a.Config()
	var list []ruleView
	for _, name := range rules.RuleNames() {
		c := cfg.Rules.Lookup(name)
		list = append(list, ruleView{Name: name, Title: ruleText[name][0], Description: ruleText[name][1],
			Enabled: c.Enabled, Severity: c.Severity, CooldownMin: c.CooldownMin, Notify: c.Notify,
			Params: ruleParams(name, cfg)})
	}
	a.mu.RLock()
	loaded := a.loadedAt.Unix()
	a.mu.RUnlock()
	return map[string]any{
		"path": a.path, "loadedAt": loaded, "rules": list,
		"riskyPorts":  cfg.Rules.RiskyPort.Ports,
		"channels":    a.currentNotifier().Channels(),
		"minSeverity": cfg.Notify.MinSeverity,
		"suppressed":  a.suppressed.Load(),
	}
}

// ---------- HTTP API ----------

func registerRulesAPI(mux *http.ServeMux, am *Alerts, tr *Traffic) {
	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		v := am.View()
		mode, _ := tr.status()
		v["demo"] = mode == "demo"
		writeJSON(w, v)
	})
	mux.HandleFunc("/api/rules/reload", postOnly(func(w http.ResponseWriter, r *http.Request) {
		if err := am.Reload(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("/api/notify/test", postOnly(func(w http.ResponseWriter, r *http.Request) {
		res, err := am.TestNotify()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, res)
	}))
	// Demo tools: fake attacks to see the alerts without a real network. Only in -capture demo.
	mux.HandleFunc("/api/demo/attack", postOnly(func(w http.ResponseWriter, r *http.Request) {
		if err := tr.DemoAttack(r.URL.Query().Get("kind")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
}

// randomLANAddr returns a made-up address inside the local network (demo tools).
func randomLANAddr(base [4]byte, lo, hi int) [4]byte {
	base[3] = byte(lo + rand.Intn(hi-lo+1))
	return base
}
