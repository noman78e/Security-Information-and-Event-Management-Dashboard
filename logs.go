package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"homesiem/logcollect"
	"homesiem/rules"
	"homesiem/store"
)

// allowFunc decides which machines may send logs. With an empty list, only
// machines on private networks (and this computer) are accepted, so a
// HomeSIEM box that is reachable from the internet is not flooded with fake logs.
func allowFunc(list []string) func(netip.Addr) bool {
	var prefixes []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p)
		} else if a, err := netip.ParseAddr(s); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
		} else {
			log.Printf("syslog: ignoring invalid -syslog-allow entry %q", s)
		}
	}
	return func(ip netip.Addr) bool {
		if ip.IsLoopback() {
			return true
		}
		if len(prefixes) == 0 {
			return ip.IsPrivate() || ip.IsLinkLocalUnicast()
		}
		for _, p := range prefixes {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
}

// Collector receives logs from other machines, keeps them in the database
// and checks them against the log rules.
type Collector struct {
	st      *store.Store
	hub     *Hub
	am      *Alerts
	srv     *logcollect.Server
	matcher *rules.LogMatcher
	in      chan logcollect.Message

	addr     string
	days     int
	maxRows  int
	stored   atomic.Uint64
	qDropped atomic.Uint64
}

func NewCollector(st *store.Store, hub *Hub, am *Alerts, addr string, allow []string, rate float64, days, maxRows int) *Collector {
	c := &Collector{st: st, hub: hub, am: am, addr: addr, days: days, maxRows: maxRows,
		in: make(chan logcollect.Message, 4096)}
	c.matcher = rules.NewLogMatcher(am.Config, func(a rules.Alert) { am.Fire(a) })
	if addr != "" && addr != "off" {
		c.srv = logcollect.NewServer(addr, allowFunc(allow), c.add, rate)
	}
	return c
}

func (c *Collector) add(m logcollect.Message) {
	select {
	case c.in <- m:
	default:
		c.qDropped.Add(1) // the database cannot keep up: drop instead of blocking the network
	}
}

func (c *Collector) Start() {
	if c.srv == nil {
		log.Printf("log collection: off")
		return
	}
	if err := c.srv.Start(); err != nil {
		log.Printf("log collection could not start: %v", err)
		emit(c.st, c.hub, "logs", "warn", fmt.Sprintf("Log receiver could not start on %s: %v. "+
			"Port 514 needs administrator rights on Linux; try -syslog 0.0.0.0:5514", c.addr, err))
		c.srv = nil
		return
	}
	log.Printf("log collection: listening on %s", strings.Join(c.srv.Listening, ", "))
	emit(c.st, c.hub, "logs", "info", "Log receiver listening on "+strings.Join(c.srv.Listening, ", "))
	go c.writer()
	go c.retention()
	go c.dropReporter()
}

// writer saves messages in batches (one disk write per second, not one per
// message) and runs the log rules on each one.
func (c *Collector) writer() {
	batch := make([]store.LogRow, 0, 200)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := c.st.AddLogs(batch); err != nil {
			log.Printf("store logs: %v", err)
		} else {
			c.stored.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}
	for {
		select {
		case m := <-c.in:
			batch = append(batch, store.LogRow{TS: m.Time.Unix(), SrcIP: m.SrcIP, Host: m.Host, Program: m.Program,
				Facility: m.Facility, Severity: m.Severity, Message: m.Text})
			c.matcher.Observe(m.Host, m.SrcIP, m.Program, m.Text, m.Time)
			if len(batch) >= 200 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (c *Collector) retention() {
	for {
		before := time.Now().AddDate(0, 0, -c.days).Unix()
		if n, err := c.st.PurgeLogs(before, c.maxRows); err != nil {
			log.Printf("log retention: %v", err)
		} else if n > 0 {
			log.Printf("log retention: removed %d old log messages", n)
		}
		time.Sleep(10 * time.Minute)
	}
}

func (c *Collector) dropReporter() {
	var last uint64
	for range time.Tick(time.Minute) {
		total := c.srv.Dropped.Load() + c.qDropped.Load()
		if total > last {
			emit(c.st, c.hub, "logs", "warn", fmt.Sprintf(
				"Log receiver dropped %d messages in the last minute (a sender over its rate limit, a sender that is not allowed, or a full queue)",
				total-last))
		}
		last = total
	}
}

// Status describes the receiver for the dashboard.
func (c *Collector) Status() map[string]any {
	st := map[string]any{"enabled": c.srv != nil, "listening": []string{}, "port": ""}
	if c.srv != nil {
		st["listening"] = c.srv.Listening
		st["port"] = c.srv.UDPPort()
		st["received"] = c.srv.Received.Load()
		st["dropped"] = c.srv.Dropped.Load() + c.qDropped.Load()
	}
	st["stored"] = c.stored.Load()
	return st
}

// SendTest sends sample messages to this program's own receiver, so you can
// check that logs arrive and that the log rules work, without a router.
func (c *Collector) SendTest(kind string) error {
	if c.srv == nil {
		return errors.New("the log receiver is not running (see the Logs page)")
	}
	conn, err := net.Dial("udp", "127.0.0.1:"+c.srv.UDPPort())
	if err != nil {
		return err
	}
	defer conn.Close()
	stamp := time.Now().Format("Jan _2 15:04:05")
	switch kind {
	case "message":
		_, err = fmt.Fprintf(conn, "<14>%s homesiem-test test[1]: Hello! This is a test log message from the HomeSIEM button.", stamp)
	case "bruteforce":
		for i := 0; i < 6 && err == nil; i++ {
			_, err = fmt.Fprintf(conn, "<38>%s testbox sshd[999]: Failed password for root from 203.0.113.50 port %d ssh2", stamp, 40000+i)
			time.Sleep(20 * time.Millisecond)
		}
	default:
		return fmt.Errorf("unknown test %q", kind)
	}
	return err
}

// ---------- HTTP API ----------

func registerLogsAPI(mux *http.ServeMux, st *store.Store, col *Collector) {
	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		lq := store.LogQuery{Text: q.Get("q"), Host: q.Get("host"), Program: q.Get("program"), MaxSeverity: -1}
		if len(lq.Text) > 200 {
			lq.Text = lq.Text[:200]
		}
		if v, err := strconv.Atoi(q.Get("level")); err == nil && v >= 0 && v <= 7 {
			lq.MaxSeverity = v
		}
		if h, err := strconv.Atoi(q.Get("hours")); err == nil && h > 0 {
			lq.Since = time.Now().Add(-time.Duration(h) * time.Hour).Unix()
		}
		if b, err := strconv.ParseInt(q.Get("before"), 10, 64); err == nil && b > 0 {
			lq.BeforeID = b
		}
		lq.Limit, _ = strconv.Atoi(q.Get("limit"))
		rows, err := st.SearchLogs(lq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"logs": rows})
	})
	mux.HandleFunc("/api/logs/sources", func(w http.ResponseWriter, r *http.Request) {
		src, err := st.LogSources()
		if err != nil {
			src = []store.LogSource{}
		}
		writeJSON(w, map[string]any{"sources": src, "status": col.Status(), "total": st.LogCount()})
	})
	mux.HandleFunc("/api/logs/test", postOnly(func(w http.ResponseWriter, r *http.Request) {
		if err := col.SendTest(r.URL.Query().Get("kind")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
}
