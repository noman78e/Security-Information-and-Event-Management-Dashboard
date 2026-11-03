package main

import (
	"crypto/tls"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"homesiem/agent"
	"homesiem/auth"
	"homesiem/discovery"
	"homesiem/fw"
	"homesiem/rules"
	"homesiem/store"
	"homesiem/tlsutil"
)

//go:embed web
var webFiles embed.FS

// version is set when building: go build -ldflags "-X main.version=1.0.0"
var version = "dev"

// shutdownHooks run when you press Ctrl+C (for example: leave the network
// card the way we found it).
var shutdownHooks []func()

// Tick is the live stats message sent to the dashboard every second.
type Tick struct {
	Type       string `json:"type"`
	Time       string `json:"time"`
	UptimeSec  int64  `json:"uptimeSec"`
	MemMB      string `json:"memMB"`
	Goroutines int    `json:"goroutines"`
	Clients    int    `json:"clients"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	CPUs       int    `json:"cpus"`
	Devices    int    `json:"devices"`
	Online     int    `json:"online"`
	Alerts     int    `json:"alerts"`
	Ports      int    `json:"ports"`
	Blocked    int    `json:"blocked"`
	Limited    int    `json:"limited"`
	DBKB       int64  `json:"dbKB"`
}

// EventMsg is a stored event pushed live to the dashboards.
type EventMsg struct {
	Type string `json:"type"`
	store.Event
}

// emit stores a log event and pushes it to every open dashboard.
func emit(st *store.Store, h *Hub, source, level, msg string) {
	e, err := st.AddEvent(source, level, msg)
	if err != nil {
		log.Printf("store event: %v", err)
		return
	}
	h.BroadcastJSON(EventMsg{Type: "event", Event: e})
}

func runTicker(h *Hub, st *store.Store, start time.Time, window int64) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var ms runtime.MemStats
	var cache Tick // database numbers, refreshed every 3 seconds
	n := 0
	for now := range t.C {
		if h.ClientCount() == 0 {
			continue // nobody is looking at the dashboard: spend no CPU on statistics
		}
		if n%3 == 0 {
			runtime.ReadMemStats(&ms)
			cache.MemMB = fmt.Sprintf("%.1f", float64(ms.Sys)/1024/1024)
			cache.Devices, cache.Alerts = st.Counts()
			cache.Online = st.OnlineCount(now.Unix() - window)
			cache.Ports = st.PortCount()
			cache.Blocked, cache.Limited = st.AccessCounts()
			cache.DBKB = st.SizeBytes() / 1024
		}
		n++
		tick := cache
		tick.Type = "tick"
		tick.Time = now.Format("15:04:05")
		tick.UptimeSec = int64(time.Since(start).Seconds())
		tick.Goroutines = runtime.NumGoroutine()
		tick.Clients = h.ClientCount()
		tick.OS, tick.Arch, tick.CPUs = runtime.GOOS, runtime.GOARCH, runtime.NumCPU()
		h.BroadcastJSON(tick)
	}
}

// runRetention deletes old data on start and then every hour.
func runRetention(st *store.Store, eventDays, alertDays, flowHours int) {
	for {
		st.PurgeDestSeen(time.Now().AddDate(0, 0, -180).Unix())
		n, err := st.Purge(eventDays, alertDays, flowHours)
		if err != nil {
			log.Printf("retention: %v", err)
		} else if n > 0 {
			log.Printf("retention: removed %d old rows", n)
		}
		time.Sleep(time.Hour)
	}
}

func main() {
	// "homesiem agent ..." runs the small log forwarder instead of the dashboard.
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		agent.Run(os.Args[2:])
		return
	}
	// "homesiem passwd" sets a new dashboard password, "homesiem bench" measures this computer.
	if len(os.Args) > 1 && os.Args[1] == "passwd" {
		runPasswd(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "bench" {
		runBench()
		return
	}
	// "homesiem unblock" is the emergency exit: it removes every block, even if the dashboard cannot be reached.
	if len(os.Args) > 1 && os.Args[1] == "unblock" {
		runUnblock(os.Args[2:])
		return
	}
	addr := flag.String("addr", "127.0.0.1:8080", "listen address (use 0.0.0.0:8080 to allow other devices on your network)")
	dbPath := flag.String("db", "homesiem.db", "path to the SQLite database file")
	eventDays := flag.Int("retain-days", 7, "days to keep events")
	alertDays := flag.Int("retain-alert-days", 30, "days to keep alerts")
	iface := flag.String("iface", "", "network interface to scan (default: the one with your internet route)")
	scanSecs := flag.Int("scan-interval", 60, "seconds between automatic scans (minimum 15)")
	workers := flag.Int("workers", 20, "how many devices to probe at the same time")
	ouiPath := flag.String("oui", "", "optional IEEE oui.csv/oui.txt file for a complete vendor list")
	portMinutes := flag.Int("port-interval", 360, "minutes between automatic port scans of each device (0 = only when you click Scan ports)")
	portRate := flag.Int("port-rate", 200, "maximum port connection attempts per second (all devices together)")
	portConc := flag.Int("port-conc", 10, "ports tried at the same time on one device")
	captureMode := flag.String("capture", "auto", "packet capture: auto (live on Linux), off, or demo (simulated traffic)")
	captureIface := flag.String("capture-iface", "", "interface to capture on (default: the scanned network's interface)")
	promisc := flag.Bool("promisc", false, "capture in promiscuous mode (needed on a switch mirror/SPAN port)")
	flowSecs := flag.Int("flow-interval", 60, "seconds between saving traffic flows to the database (minimum 10)")
	flowRows := flag.Int("flow-rows", 500, "maximum flow rows saved per interval (the rest are added together in one row)")
	maxFlows := flag.Int("max-flows", 20000, "maximum distinct flows kept in memory")
	flowHours := flag.Int("retain-flow-hours", 24, "hours to keep saved traffic flows")
	rulesPath := flag.String("rules", "rules.yaml", "alert rules file (created with defaults on first start)")
	enforce := flag.String("enforce", "auto", "blocking and speed limits: auto (real firewall rules on a Linux gateway running as root), dry-run (show only), or off")
	releaseOnExit := flag.Bool("release-on-exit", false, "remove all blocks when HomeSIEM stops (by default they stay in force)")
	syslogAddr := flag.String("syslog", "0.0.0.0:514", "receive logs from routers and other machines on this address (UDP and TCP); \"off\" to disable. Port 514 needs administrator rights, otherwise 5514 is used")
	syslogAllow := flag.String("syslog-allow", "", "comma-separated addresses or networks allowed to send logs (default: private networks only)")
	syslogRate := flag.Float64("syslog-rate", 200, "maximum log messages per second accepted from one sender")
	logDays := flag.Int("log-days", 7, "days to keep received logs")
	logRows := flag.Int("log-max-rows", 100000, "maximum number of received log messages kept")
	tlsMode := flag.String("tls", "auto", "HTTPS: auto (on whenever the dashboard is reachable from other computers), self (always, with a self-signed certificate), or off")
	tlsCert := flag.String("tls-cert", "", "use your own HTTPS certificate file (together with -tls-key)")
	tlsKey := flag.String("tls-key", "", "private key file for -tls-cert")
	noAuth := flag.Bool("no-auth", false, "turn the sign-in off (only allowed when the dashboard listens on 127.0.0.1)")
	memLimit := flag.Int("mem-limit", 200, "soft memory limit in MB: the program works harder to stay below it (0 = none)")
	showVersion := flag.Bool("version", false, "show the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("HomeSIEM", version)
		return
	}
	if *memLimit > 0 {
		debug.SetMemoryLimit(int64(*memLimit) << 20)
	}

	if *scanSecs < 15 {
		*scanSecs = 15
	}
	scanEvery := time.Duration(*scanSecs) * time.Second
	window := int64(scanEvery.Seconds() * 2.5) // "online" = seen within 2.5 scans

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("cannot open database %q: %v", *dbPath, err)
	}
	log.Printf("database ready: %s", *dbPath)

	if *ouiPath != "" {
		n, err := discovery.LoadOUIFile(*ouiPath)
		if err != nil {
			log.Printf("vendor list: %v", err)
		} else {
			log.Printf("vendor list: loaded %d entries from %s", n, *ouiPath)
		}
	}

	// Close the database cleanly on Ctrl+C so nothing is left half-written.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("shutting down...")
		for _, f := range shutdownHooks {
			f()
		}
		st.Close()
		os.Exit(0)
	}()

	hub := NewHub()
	emit(st, hub, "core", "info", "HomeSIEM started")
	am := NewAlerts(st, hub, *rulesPath)

	go runTicker(hub, st, time.Now(), window)
	go runRetention(st, *eventDays, *alertDays, *flowHours)

	var disc *Discovery
	netw, err := discovery.LocalNetwork(*iface)
	if err != nil {
		log.Printf("device discovery disabled: %v", err)
		emit(st, hub, "discovery", "error", "Device discovery disabled: "+err.Error())
	} else {
		log.Printf("scanning network %s (%d hosts), every %ds, %d at a time",
			netw, len(netw.Hosts()), *scanSecs, *workers)
		emit(st, hub, "discovery", "info", "Monitoring network "+netw.String())
		disc = NewDiscovery(st, hub, netw, *workers, scanEvery, am)
		go disc.Run()
	}

	ps := NewPortScanner(st, hub, *workers, *portConc, *portRate,
		time.Duration(*portMinutes)*time.Minute, window, am)
	go ps.Run()
	if *portMinutes > 0 {
		log.Printf("port scanning: every %d min, %d devices at a time, max %d attempts/s",
			*portMinutes, *workers, *portRate)
	} else {
		log.Printf("port scanning: manual only")
	}

	switch *captureMode {
	case "auto", "off", "demo":
	default:
		log.Fatalf("unknown -capture %q (use auto, off or demo)", *captureMode)
	}
	if *flowSecs < 10 {
		*flowSecs = 10
	}
	tr := NewTraffic(st, hub, TrafficConfig{
		Mode: *captureMode, Iface: *captureIface, Promisc: *promisc,
		FlushEvery: time.Duration(*flowSecs) * time.Second, MaxRows: *flowRows, MaxFlows: *maxFlows,
	}, netw, am)
	shutdownHooks = append(shutdownHooks, tr.Close)
	tr.Start()

	ac := NewAccess(st, hub, *enforce, netw)
	ac.Start()
	if *releaseOnExit {
		shutdownHooks = append(shutdownHooks, func() { fw.Remove() })
	}

	col := NewCollector(st, hub, am, *syslogAddr, strings.Split(*syslogAllow, ","), *syslogRate, *logDays, *logRows)
	col.Start()

	// ---- HTTPS and sign-in ----
	loopback := isLoopbackAddr(*addr)
	useTLS, certPath, keyPath := false, *tlsCert, *tlsKey
	if (certPath == "") != (keyPath == "") {
		log.Fatal("-tls-cert and -tls-key must be given together")
	}
	switch *tlsMode {
	case "auto", "self", "off":
	default:
		log.Fatalf("unknown -tls %q (use auto, self or off)", *tlsMode)
	}
	switch {
	case certPath != "":
		useTLS = true
	case *tlsMode == "self" || (*tlsMode == "auto" && !loopback):
		useTLS = true
		dir := filepath.Dir(*dbPath)
		certPath, keyPath = filepath.Join(dir, "homesiem-cert.pem"), filepath.Join(dir, "homesiem-key.pem")
		fp, err := tlsutil.Ensure(certPath, keyPath)
		if err != nil {
			log.Fatalf("cannot create the HTTPS certificate: %v", err)
		}
		log.Printf("HTTPS certificate fingerprint (SHA-256): %s", fp)
	}

	var authMgr *auth.Manager
	if *noAuth {
		if !loopback {
			log.Fatal("-no-auth is only allowed when the dashboard listens on this computer only (-addr 127.0.0.1:8080)")
		}
		log.Printf("WARNING: sign-in is turned off (-no-auth). Anyone using this computer can control HomeSIEM.")
	} else {
		var err error
		authMgr, err = auth.New(st, useTLS)
		if err != nil {
			log.Fatalf("sign-in could not start: %v", err)
		}
		authMgr.Log = func(level, msg string) { emit(st, hub, "auth", level, msg) }
		authMgr.Lockout = func(ip string, minutes int) {
			am.Fire(rules.Alert{Rule: "login_lockout", Key: ip, IP: ip, Message: fmt.Sprintf(
				"Dashboard sign-in locked for %d minutes after repeated wrong passwords from %s", minutes, ip)})
		}
		if code := authMgr.SetupCode(); code != "" {
			codePath := filepath.Join(filepath.Dir(*dbPath), "setup-code.txt")
			os.WriteFile(codePath, []byte(code+"\n"), 0o600)
			log.Printf("==============================================================")
			log.Printf(" FIRST START. Open the dashboard and create your password.")
			log.Printf(" Setup code: %s   (also saved in %s)", code, codePath)
			log.Printf("==============================================================")
			go func() { // the code is only good once: remove the file when the password exists
				for authMgr.SetupCode() != "" {
					time.Sleep(10 * time.Second)
				}
				os.Remove(codePath)
			}()
		}
	}

	sub, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		page, err := fs.ReadFile(sub, "login.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})
	mux.HandleFunc("/api/about", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"version": version, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH})
	})
	if authMgr != nil {
		mux.HandleFunc("/api/login", authMgr.HandleLogin)
		mux.HandleFunc("/api/setup", authMgr.HandleSetup)
		mux.HandleFunc("/api/logout", authMgr.HandleLogout)
		mux.HandleFunc("/api/password", authMgr.HandleChangePassword)
		mux.HandleFunc("/api/auth/status", authMgr.HandleStatus)
	} else {
		mux.HandleFunc("/api/auth/status", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]bool{"authRequired": false, "setupRequired": false, "authenticated": true})
		})
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/events", hub.serveEvents)
	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
		evs, err := st.RecentEvents(limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, evs)
	})
	registerAPI(mux, st, disc, window, ac)
	registerAccessAPI(mux, ac)
	registerPortAPI(mux, st, ps)
	registerTrafficAPI(mux, st, tr)
	registerRulesAPI(mux, am, tr)
	registerLogsAPI(mux, st, col)

	var handler http.Handler = mux
	if authMgr != nil {
		handler = authMgr.Protect(handler)
	}
	handler = securityHeaders(handler)

	srv := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}
	scheme := "http"
	if useTLS {
		scheme = "https"
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	log.Printf("HomeSIEM %s dashboard: %s://%s  (%s/%s)", version, scheme, *addr, runtime.GOOS, runtime.GOARCH)
	if !useTLS && !loopback {
		log.Printf("WARNING: the dashboard is reachable from other computers WITHOUT encryption (-tls off). Passwords can be read from the network.")
	}
	if useTLS {
		log.Fatal(srv.ListenAndServeTLS(certPath, keyPath))
	}
	log.Fatal(srv.ListenAndServe())
}

// isLoopbackAddr is true when the address only accepts connections from this computer.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// securityHeaders adds the browser protections that fit this dashboard: no
// framing, no guessing of file types, scripts only from this server, and no
// caching of data from the API.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/api/" || r.URL.Path == "/events" {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// runUnblock removes every block and speed limit: it clears them in the
// database (so they are not re-applied at the next start) and deletes the
// firewall table. Run it with sudo: sudo ./homesiem unblock
func runUnblock(args []string) {
	fs := flag.NewFlagSet("unblock", flag.ExitOnError)
	dbPath := fs.String("db", "homesiem.db", "path to the HomeSIEM database")
	fs.Parse(args)
	failed := false
	if st, err := store.Open(*dbPath); err != nil {
		fmt.Fprintf(os.Stderr, "could not open the database %s: %v\n", *dbPath, err)
		failed = true
	} else {
		if err := st.ClearAccess(); err != nil {
			fmt.Fprintf(os.Stderr, "could not clear the saved blocks: %v\n", err)
			failed = true
		} else {
			fmt.Println("saved blocks and speed limits cleared")
		}
		st.Close()
	}
	if err := fw.Remove(); err != nil {
		fmt.Fprintf(os.Stderr, "%v (run this command with sudo)\n", err)
		failed = true
	} else {
		fmt.Println("firewall rules removed")
	}
	if failed {
		os.Exit(1)
	}
}
