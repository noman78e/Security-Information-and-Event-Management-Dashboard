// Package store wraps SQLite (pure Go driver, no CGO) for HomeSIEM.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

// Event is one stored log line.
type Event struct {
	ID      int64  `json:"id"`
	TS      int64  `json:"ts"` // unix seconds
	Source  string `json:"source"`
	Level   string `json:"level"` // info | warn | error
	Message string `json:"message"`
}

// migrations are applied in order, once each. NEVER edit an old entry:
// to change the schema later, append a new entry at the end.
var migrations = [][]string{
	{ // version 1: initial schema
		`CREATE TABLE devices (
			id         INTEGER PRIMARY KEY,
			mac        TEXT NOT NULL UNIQUE,
			ip         TEXT NOT NULL DEFAULT '',
			hostname   TEXT NOT NULL DEFAULT '',
			vendor     TEXT NOT NULL DEFAULT '',
			first_seen INTEGER NOT NULL,
			last_seen  INTEGER NOT NULL,
			trusted    INTEGER NOT NULL DEFAULT 0,
			blocked    INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE events (
			id      INTEGER PRIMARY KEY,
			ts      INTEGER NOT NULL,
			source  TEXT NOT NULL,
			level   TEXT NOT NULL,
			message TEXT NOT NULL
		)`,
		`CREATE INDEX idx_events_ts ON events(ts)`,
		`CREATE TABLE alerts (
			id           INTEGER PRIMARY KEY,
			ts           INTEGER NOT NULL,
			severity     TEXT NOT NULL,
			rule         TEXT NOT NULL,
			device_mac   TEXT NOT NULL DEFAULT '',
			message      TEXT NOT NULL,
			acknowledged INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX idx_alerts_ts ON alerts(ts)`,
		`CREATE TABLE flows (
			id       INTEGER PRIMARY KEY,
			ts       INTEGER NOT NULL,
			src_ip   TEXT NOT NULL,
			dst_ip   TEXT NOT NULL,
			dst_port INTEGER NOT NULL DEFAULT 0,
			proto    TEXT NOT NULL,
			bytes    INTEGER NOT NULL,
			packets  INTEGER NOT NULL
		)`,
		`CREATE INDEX idx_flows_ts ON flows(ts)`,
	},
	{ // version 2: open ports found by the port scanner
		`CREATE TABLE ports (
			id         INTEGER PRIMARY KEY,
			mac        TEXT NOT NULL,
			port       INTEGER NOT NULL,
			proto      TEXT NOT NULL DEFAULT 'tcp',
			service    TEXT NOT NULL DEFAULT '',
			banner     TEXT NOT NULL DEFAULT '',
			first_seen INTEGER NOT NULL,
			last_seen  INTEGER NOT NULL,
			UNIQUE(mac, port, proto)
		)`,
		`CREATE INDEX idx_ports_mac ON ports(mac)`,
		`ALTER TABLE devices ADD COLUMN last_port_scan INTEGER NOT NULL DEFAULT 0`,
	},
	{ // version 3: traffic direction on flows (up / down / lan / other)
		`ALTER TABLE flows ADD COLUMN dir TEXT NOT NULL DEFAULT ''`,
	},
	{ // version 4: destinations each device has talked to (for the new_destination rule)
		`CREATE TABLE dest_seen (
			dev        TEXT NOT NULL,
			remote     TEXT NOT NULL,
			port       INTEGER NOT NULL,
			first_seen INTEGER NOT NULL,
			PRIMARY KEY (dev, remote, port)
		) WITHOUT ROWID`,
	},
	{ // version 5: logs received from routers and other machines
		`CREATE TABLE logs (
			id       INTEGER PRIMARY KEY,
			ts       INTEGER NOT NULL,
			src_ip   TEXT NOT NULL,
			host     TEXT NOT NULL,
			program  TEXT NOT NULL,
			facility INTEGER NOT NULL,
			severity INTEGER NOT NULL,
			message  TEXT NOT NULL
		)`,
		`CREATE INDEX idx_logs_ts ON logs(ts)`,
		`CREATE INDEX idx_logs_host ON logs(host)`,
	},
	{ // version 6: speed limits and temporary blocks
		`ALTER TABLE devices ADD COLUMN limit_kbytes INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE devices ADD COLUMN blocked_until INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE devices ADD COLUMN block_note TEXT NOT NULL DEFAULT ''`,
	},
	{ // version 7: small settings such as the dashboard password hash
		`CREATE TABLE settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	},
}

// Open opens (or creates) the database file and applies pending migrations.
func Open(path string) (*Store, error) {
	// Pragmas are tuned for small machines: WAL for safe fast writes,
	// a ~2 MB page cache, temp data in memory, incremental auto-vacuum
	// so the file can shrink after old rows are deleted.
	dsn := path + "?_pragma=auto_vacuum(2)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=cache_size(-2000)" +
		"&_pragma=temp_store(2)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer: simplest and safest for SQLite
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	var current int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	for i := current; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range migrations[i] {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("migration %d: %w", i+1, err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`,
			i+1, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// AddEvent stores one log event and returns it (with its new ID).
func (s *Store) AddEvent(source, level, msg string) (Event, error) {
	e := Event{TS: time.Now().Unix(), Source: source, Level: level, Message: msg}
	res, err := s.db.Exec(`INSERT INTO events(ts, source, level, message) VALUES(?,?,?,?)`,
		e.TS, e.Source, e.Level, e.Message)
	if err != nil {
		return e, err
	}
	e.ID, _ = res.LastInsertId()
	return e, nil
}

// RecentEvents returns the newest events first.
func (s *Store) RecentEvents(limit int) ([]Event, error) {
	rows, err := s.db.Query(
		`SELECT id, ts, source, level, message FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.Source, &e.Level, &e.Message); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Counts returns the number of known devices and unacknowledged alerts.
func (s *Store) Counts() (devices, alerts int) {
	s.db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&devices)
	s.db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE acknowledged = 0`).Scan(&alerts)
	return
}

// SizeBytes returns the current database size.
func (s *Store) SizeBytes() int64 {
	var pages, size int64
	s.db.QueryRow(`PRAGMA page_count`).Scan(&pages)
	s.db.QueryRow(`PRAGMA page_size`).Scan(&size)
	return pages * size
}

// Purge deletes old rows (retention) and shrinks the files.
// Events are kept eventDays days, alerts alertDays days, and traffic flows
// flowHours hours (flows are by far the biggest table).
func (s *Store) Purge(eventDays, alertDays, flowHours int) (int64, error) {
	now := time.Now()
	eventCut := now.AddDate(0, 0, -eventDays).Unix()
	alertCut := now.AddDate(0, 0, -alertDays).Unix()
	flowCut := now.Add(-time.Duration(flowHours) * time.Hour).Unix()

	jobs := []struct {
		query  string
		cutoff int64
	}{
		{`DELETE FROM events WHERE ts < ?`, eventCut},
		{`DELETE FROM flows WHERE ts < ?`, flowCut},
		{`DELETE FROM alerts WHERE ts < ?`, alertCut},
	}
	var total int64
	for _, j := range jobs {
		res, err := s.db.Exec(j.query, j.cutoff)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	s.db.Exec(`PRAGMA incremental_vacuum`)
	s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return total, nil
}

// ---------- Devices ----------

// Device is one machine seen on the network.
type Device struct {
	ID        int64  `json:"id"`
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	Vendor    string `json:"vendor"`
	FirstSeen int64  `json:"firstSeen"`
	LastSeen  int64  `json:"lastSeen"`
	Trusted   bool   `json:"trusted"`
	Blocked   bool   `json:"blocked"`
	Online    bool   `json:"online"` // filled in by the API, not stored
	Self      bool   `json:"self"`   // filled in by the API, not stored

	LastPortScan int64 `json:"lastPortScan"` // unix seconds, 0 = never scanned
	OpenPorts    int   `json:"openPorts"`    // number of open ports on record

	LimitKBytes  int    `json:"limitKBytes"`  // speed limit in kilobytes/second, 0 = none
	BlockedUntil int64  `json:"blockedUntil"` // unix seconds, 0 = until unblocked by hand
	BlockNote    string `json:"blockNote"`

	Protected    bool   `json:"protected"`    // filled in by the API: cannot be blocked
	ProtectedWhy string `json:"protectedWhy"` // filled in by the API
}

// UpsertDevice inserts a new device or refreshes an existing one.
// It returns true when the device had never been seen before.
// Empty hostname/vendor never overwrite a known value.
func (s *Store) UpsertDevice(mac, ip, hostname, vendor string, now int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE devices SET ip = ?, last_seen = ?,
		hostname = CASE WHEN ? <> '' THEN ? ELSE hostname END,
		vendor   = CASE WHEN ? <> '' THEN ? ELSE vendor END
		WHERE mac = ?`, ip, now, hostname, hostname, vendor, vendor, mac)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return false, nil
	}
	_, err = s.db.Exec(`INSERT INTO devices(mac, ip, hostname, vendor, first_seen, last_seen)
		VALUES(?,?,?,?,?,?)`, mac, ip, hostname, vendor, now, now)
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListDevices returns every known device.
func (s *Store) ListDevices() ([]Device, error) {
	rows, err := s.db.Query(`SELECT d.id, d.mac, d.ip, d.hostname, d.vendor, d.first_seen, d.last_seen,
			d.trusted, d.blocked, d.last_port_scan, COALESCE(p.n, 0),
			d.limit_kbytes, d.blocked_until, d.block_note
		FROM devices d
		LEFT JOIN (SELECT mac, COUNT(*) AS n FROM ports GROUP BY mac) p ON p.mac = d.mac`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		var d Device
		var tr, bl int
		if err := rows.Scan(&d.ID, &d.MAC, &d.IP, &d.Hostname, &d.Vendor, &d.FirstSeen, &d.LastSeen, &tr, &bl, &d.LastPortScan, &d.OpenPorts,
			&d.LimitKBytes, &d.BlockedUntil, &d.BlockNote); err != nil {
			return nil, err
		}
		d.Trusted, d.Blocked = tr != 0, bl != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// OnlineCount counts devices seen since the given unix time.
func (s *Store) OnlineCount(since int64) int {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE last_seen >= ?`, since).Scan(&n)
	return n
}

// ---------- Alerts ----------

type Alert struct {
	ID           int64  `json:"id"`
	TS           int64  `json:"ts"`
	Severity     string `json:"severity"` // low | medium | high
	Rule         string `json:"rule"`
	DeviceMAC    string `json:"deviceMac"`
	Message      string `json:"message"`
	Acknowledged bool   `json:"acknowledged"`
}

func (s *Store) AddAlert(severity, rule, mac, msg string) (Alert, error) {
	a := Alert{TS: time.Now().Unix(), Severity: severity, Rule: rule, DeviceMAC: mac, Message: msg}
	res, err := s.db.Exec(`INSERT INTO alerts(ts, severity, rule, device_mac, message) VALUES(?,?,?,?,?)`,
		a.TS, a.Severity, a.Rule, a.DeviceMAC, a.Message)
	if err != nil {
		return a, err
	}
	a.ID, _ = res.LastInsertId()
	return a, nil
}

// ListAlerts returns the newest alerts first.
func (s *Store) ListAlerts(limit int) ([]Alert, error) {
	rows, err := s.db.Query(`SELECT id, ts, severity, rule, device_mac, message, acknowledged
		FROM alerts ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var ack int
		if err := rows.Scan(&a.ID, &a.TS, &a.Severity, &a.Rule, &a.DeviceMAC, &a.Message, &ack); err != nil {
			return nil, err
		}
		a.Acknowledged = ack != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) AckAlert(id int64) error {
	_, err := s.db.Exec(`UPDATE alerts SET acknowledged = 1 WHERE id = ?`, id)
	return err
}

func (s *Store) AckAllAlerts() error {
	_, err := s.db.Exec(`UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0`)
	return err
}

// ---------- Ports ----------

// Port is one open TCP port on a device.
type Port struct {
	MAC       string `json:"mac"`
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Service   string `json:"service"`
	Banner    string `json:"banner"`
	FirstSeen int64  `json:"firstSeen"`
	LastSeen  int64  `json:"lastSeen"`
}

// UpsertPort records an open port. It returns true if this port was not
// known before. An empty banner never overwrites a known one.
func (s *Store) UpsertPort(mac string, port int, service, banner string, now int64) (bool, error) {
	res, err := s.db.Exec(`UPDATE ports SET last_seen = ?, service = ?,
		banner = CASE WHEN ? <> '' THEN ? ELSE banner END
		WHERE mac = ? AND port = ? AND proto = 'tcp'`, now, service, banner, banner, mac, port)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return false, nil
	}
	_, err = s.db.Exec(`INSERT INTO ports(mac, port, proto, service, banner, first_seen, last_seen)
		VALUES(?,?,'tcp',?,?,?,?)`, mac, port, service, banner, now, now)
	if err != nil {
		return false, err
	}
	return true, nil
}

func scanPorts(rows *sql.Rows) ([]Port, error) {
	defer rows.Close()
	out := []Port{}
	for rows.Next() {
		var p Port
		if err := rows.Scan(&p.MAC, &p.Port, &p.Proto, &p.Service, &p.Banner, &p.FirstSeen, &p.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListPorts returns the open ports of one device, lowest port first.
func (s *Store) ListPorts(mac string) ([]Port, error) {
	rows, err := s.db.Query(`SELECT mac, port, proto, service, banner, first_seen, last_seen
		FROM ports WHERE mac = ? ORDER BY port`, mac)
	if err != nil {
		return nil, err
	}
	return scanPorts(rows)
}

// PruneClosedPorts removes ports of this device that were not seen since
// `before` and returns them.
func (s *Store) PruneClosedPorts(mac string, before int64) ([]Port, error) {
	rows, err := s.db.Query(`SELECT mac, port, proto, service, banner, first_seen, last_seen
		FROM ports WHERE mac = ? AND last_seen < ? ORDER BY port`, mac, before)
	if err != nil {
		return nil, err
	}
	closed, err := scanPorts(rows) // closes rows before we write
	if err != nil || len(closed) == 0 {
		return closed, err
	}
	_, err = s.db.Exec(`DELETE FROM ports WHERE mac = ? AND last_seen < ?`, mac, before)
	return closed, err
}

// SetPortScanned remembers when a device was last port-scanned.
func (s *Store) SetPortScanned(mac string, now int64) error {
	_, err := s.db.Exec(`UPDATE devices SET last_port_scan = ? WHERE mac = ?`, now, mac)
	return err
}

// PortCount returns the total number of open ports on record.
func (s *Store) PortCount() int {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM ports`).Scan(&n)
	return n
}

// ---------- Traffic flows ----------

// FlowRow is one summarized traffic flow.
type FlowRow struct {
	Src, Dst     string
	Port         int // service port
	Proto, Dir   string
	Bytes, Packets int64
}

// AddFlows saves a batch of flows in a single transaction.
func (s *Store) AddFlows(ts int64, rows []FlowRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO flows(ts, src_ip, dst_ip, dst_port, proto, bytes, packets, dir)
		VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, r := range rows {
		if _, err := stmt.Exec(ts, r.Src, r.Dst, r.Port, r.Proto, r.Bytes, r.Packets, r.Dir); err != nil {
			stmt.Close()
			tx.Rollback()
			return err
		}
	}
	stmt.Close()
	return tx.Commit()
}

// RemoteHost is an outside address your network talked to.
type RemoteHost struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"` // filled in by the API
	Up      int64  `json:"up"`      // bytes your network sent to it
	Down    int64  `json:"down"`    // bytes it sent to your network
	Packets int64  `json:"packets"`
}

// TopRemote returns the busiest outside hosts since the given time.
func (s *Store) TopRemote(since int64, limit int) ([]RemoteHost, error) {
	rows, err := s.db.Query(`SELECT
			CASE WHEN dir = 'up' THEN dst_ip ELSE src_ip END AS remote,
			dst_port, proto,
			SUM(CASE WHEN dir = 'up' THEN bytes ELSE 0 END),
			SUM(CASE WHEN dir = 'down' THEN bytes ELSE 0 END),
			SUM(packets)
		FROM flows WHERE ts >= ? AND dir IN ('up', 'down')
		GROUP BY remote, dst_port, proto
		ORDER BY SUM(bytes) DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RemoteHost{}
	for rows.Next() {
		var h RemoteHost
		if err := rows.Scan(&h.Host, &h.Port, &h.Proto, &h.Up, &h.Down, &h.Packets); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ---------- Learned destinations ----------

// DestRow is one (device, outside address, port) combination a device has used.
type DestRow struct {
	Dev       string // device MAC, or its IP if the MAC is not known
	Remote    string
	Port      int
	FirstSeen int64
}

// LoadDestSeen returns up to limit remembered destinations.
func (s *Store) LoadDestSeen(limit int) ([]DestRow, error) {
	rows, err := s.db.Query(`SELECT dev, remote, port, first_seen FROM dest_seen LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DestRow
	for rows.Next() {
		var r DestRow
		if err := rows.Scan(&r.Dev, &r.Remote, &r.Port, &r.FirstSeen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DestLearnStarts returns, per device, when its first destination was recorded.
func (s *Store) DestLearnStarts() (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT dev, MIN(first_seen) FROM dest_seen GROUP BY dev`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var dev string
		var t int64
		if err := rows.Scan(&dev, &t); err != nil {
			return nil, err
		}
		out[dev] = t
	}
	return out, rows.Err()
}

// AddDestSeen remembers destinations (existing ones are left alone).
func (s *Store) AddDestSeen(rows []DestRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO dest_seen(dev, remote, port, first_seen) VALUES(?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, r := range rows {
		if _, err := stmt.Exec(r.Dev, r.Remote, r.Port, r.FirstSeen); err != nil {
			stmt.Close()
			tx.Rollback()
			return err
		}
	}
	stmt.Close()
	return tx.Commit()
}

// PurgeDestSeen forgets destinations older than the given unix time.
func (s *Store) PurgeDestSeen(before int64) error {
	_, err := s.db.Exec(`DELETE FROM dest_seen WHERE first_seen < ?`, before)
	return err
}

// ---------- Collected logs ----------

// LogRow is one log message received from another machine.
type LogRow struct {
	ID       int64  `json:"id"`
	TS       int64  `json:"ts"`
	SrcIP    string `json:"srcIp"`
	Host     string `json:"host"`
	Program  string `json:"program"`
	Facility int    `json:"facility"`
	Severity int    `json:"severity"` // 0 emergency ... 7 debug
	Message  string `json:"message"`
}

// AddLogs saves a batch of log messages in one transaction.
func (s *Store) AddLogs(rows []LogRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO logs(ts, src_ip, host, program, facility, severity, message)
		VALUES(?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, r := range rows {
		if _, err := stmt.Exec(r.TS, r.SrcIP, r.Host, r.Program, r.Facility, r.Severity, r.Message); err != nil {
			stmt.Close()
			tx.Rollback()
			return err
		}
	}
	stmt.Close()
	return tx.Commit()
}

// LogQuery describes a log search.
type LogQuery struct {
	Text        string // every word must appear in the message, host or program
	Host        string
	Program     string
	MaxSeverity int   // -1 = any; otherwise only messages this severe or worse (lower number = worse)
	Since       int64 // unix seconds, 0 = no limit
	BeforeID    int64 // for paging: only messages older than this id
	Limit       int
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// SearchLogs returns matching messages, newest first.
func (s *Store) SearchLogs(q LogQuery) ([]LogRow, error) {
	where := []string{"1=1"}
	var args []any
	if q.Since > 0 {
		where = append(where, "ts >= ?")
		args = append(args, q.Since)
	}
	if q.BeforeID > 0 {
		where = append(where, "id < ?")
		args = append(args, q.BeforeID)
	}
	if q.Host != "" {
		where = append(where, "(host = ? OR src_ip = ?)")
		args = append(args, q.Host, q.Host)
	}
	if q.Program != "" {
		where = append(where, "program = ?")
		args = append(args, q.Program)
	}
	if q.MaxSeverity >= 0 {
		where = append(where, "severity <= ?")
		args = append(args, q.MaxSeverity)
	}
	words := strings.Fields(q.Text)
	if len(words) > 6 {
		words = words[:6]
	}
	for _, w := range words {
		pat := "%" + likeEscape(w) + "%"
		where = append(where, `(message LIKE ? ESCAPE '\' OR host LIKE ? ESCAPE '\' OR program LIKE ? ESCAPE '\')`)
		args = append(args, pat, pat, pat)
	}
	limit := q.Limit
	if limit < 1 || limit > 500 {
		limit = 100
	}
	args = append(args, limit)
	rows, err := s.db.Query(`SELECT id, ts, src_ip, host, program, facility, severity, message
		FROM logs WHERE `+strings.Join(where, " AND ")+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LogRow{}
	for rows.Next() {
		var r LogRow
		if err := rows.Scan(&r.ID, &r.TS, &r.SrcIP, &r.Host, &r.Program, &r.Facility, &r.Severity, &r.Message); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LogSource is a machine that sends logs.
type LogSource struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
	Last  int64  `json:"last"`
}

// LogSources lists the machines that sent logs, busiest first.
func (s *Store) LogSources() ([]LogSource, error) {
	rows, err := s.db.Query(`SELECT host, COUNT(*), MAX(ts) FROM logs GROUP BY host ORDER BY COUNT(*) DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LogSource{}
	for rows.Next() {
		var l LogSource
		if err := rows.Scan(&l.Host, &l.Count, &l.Last); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// LogCount returns how many log messages are stored.
func (s *Store) LogCount() int {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM logs`).Scan(&n)
	return n
}

// PurgeLogs deletes messages older than `before`, and then the oldest ones
// beyond maxRows, so the table can never grow without limit.
func (s *Store) PurgeLogs(before int64, maxRows int) (int64, error) {
	var total int64
	res, err := s.db.Exec(`DELETE FROM logs WHERE ts < ?`, before)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	total += n
	if maxRows > 0 {
		res, err = s.db.Exec(`DELETE FROM logs WHERE id <= (SELECT id FROM logs ORDER BY id DESC LIMIT 1 OFFSET ?)`, maxRows)
		if err != nil {
			return total, err
		}
		n, _ = res.RowsAffected()
		total += n
	}
	return total, nil
}

// ---------- Access control ----------

// SetBlocked blocks or unblocks a device. until is a unix time when the block
// ends by itself (0 = until someone unblocks it).
func (s *Store) SetBlocked(mac string, blocked bool, until int64, note string) error {
	b := 0
	if blocked {
		b = 1
	} else {
		until, note = 0, ""
	}
	_, err := s.db.Exec(`UPDATE devices SET blocked = ?, blocked_until = ?, block_note = ? WHERE mac = ?`, b, until, note, mac)
	return err
}

// SetTrusted marks a device as protected: it can never be blocked.
func (s *Store) SetTrusted(mac string, on bool) error {
	v := 0
	if on {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE devices SET trusted = ? WHERE mac = ?`, v, mac)
	return err
}

// SetLimit sets a speed limit in kilobytes per second (0 removes it).
func (s *Store) SetLimit(mac string, kbytes int) error {
	_, err := s.db.Exec(`UPDATE devices SET limit_kbytes = ? WHERE mac = ?`, kbytes, mac)
	return err
}

// ClearAccess removes every block and speed limit.
func (s *Store) ClearAccess() error {
	_, err := s.db.Exec(`UPDATE devices SET blocked = 0, blocked_until = 0, block_note = '', limit_kbytes = 0`)
	return err
}

// ExpiredBlocks lists blocked devices whose time is up.
func (s *Store) ExpiredBlocks(now int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT mac FROM devices WHERE blocked = 1 AND blocked_until > 0 AND blocked_until <= ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AccessCounts returns how many devices are blocked and how many are speed limited.
func (s *Store) AccessCounts() (blocked, limited int) {
	s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE blocked = 1`).Scan(&blocked)
	s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE blocked = 0 AND limit_kbytes > 0`).Scan(&limited)
	return
}

// ---------- Settings ----------

// GetSetting returns a saved setting, or "" if it does not exist.
func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SetSetting saves a setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
