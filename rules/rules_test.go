package rules

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"homesiem/capture"
)

func collect() (func(Alert), *[]Alert) {
	var got []Alert
	return func(a Alert) { got = append(got, a) }, &got
}

// The built-in rules file must match the Go settings exactly (no typos).
func TestDefaultYAMLIsStrictlyValid(t *testing.T) {
	dec := yaml.NewDecoder(bytes.NewReader(DefaultYAML))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("default_rules.yaml does not match the settings: %v", err)
	}
	d := Defaults()
	if !d.Rules.PortScan.Enabled || d.Rules.PortScan.PortThreshold != 20 || d.Rules.RiskyPort.Ports[0] != 21 {
		t.Fatalf("defaults not loaded: %+v", d.Rules.PortScan)
	}
	if d.Rules.NewDestination.IgnorePorts[3] != 443 || d.Notify.MinSeverity != "high" {
		t.Fatalf("defaults not loaded correctly")
	}
	for _, name := range RuleNames() {
		if d.Rules.Lookup(name) == nil {
			t.Fatalf("rule %s has no settings", name)
		}
	}
}

func syn(src, dst string, port uint16) capture.Packet {
	return capture.Packet{IP: true, Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst),
		SrcPort: 50000, DstPort: port, Proto: capture.ProtoTCP, TCPFlags: 0x02}
}

func TestPortScanDetected(t *testing.T) {
	cfg := Defaults()
	emit, got := collect()
	d := NewPortScanDetector(func() *Config { return cfg }, emit, netip.MustParseAddr("192.168.1.2"))
	now := time.Now()
	for port := 1; port <= 25; port++ {
		d.ObserveAt(syn("192.168.1.40", "192.168.1.16", uint16(port)), now)
	}
	if len(*got) != 1 || (*got)[0].Rule != "port_scan" || (*got)[0].IP != "192.168.1.40" {
		t.Fatalf("expected exactly one port_scan alert, got %+v", *got)
	}
}

func TestSweepDetected(t *testing.T) {
	cfg := Defaults()
	emit, got := collect()
	d := NewPortScanDetector(func() *Config { return cfg }, emit, netip.MustParseAddr("192.168.1.2"))
	now := time.Now()
	for host := 1; host <= 40; host++ {
		d.ObserveAt(syn("192.168.1.40", "192.168.1."+itoa(host+100), 22), now)
	}
	if len(*got) != 1 {
		t.Fatalf("expected one sweep alert, got %d", len(*got))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestOwnScansAndNormalTrafficAreIgnored(t *testing.T) {
	cfg := Defaults()
	emit, got := collect()
	self := netip.MustParseAddr("192.168.1.2")
	d := NewPortScanDetector(func() *Config { return cfg }, emit, self)
	now := time.Now()
	for port := 1; port <= 60; port++ {
		d.ObserveAt(syn("192.168.1.2", "192.168.1.16", uint16(port)), now) // HomeSIEM itself
	}
	for port := 1; port <= 10; port++ { // a few ports only: normal
		d.ObserveAt(syn("192.168.1.40", "192.168.1.16", uint16(port)), now)
	}
	ack := syn("192.168.1.50", "192.168.1.16", 80)
	ack.TCPFlags = 0x12 // SYN+ACK reply, not a connection attempt
	for i := 0; i < 100; i++ {
		ack.DstPort = uint16(1000 + i)
		d.ObserveAt(ack, now)
	}
	if len(*got) != 0 {
		t.Fatalf("expected no alerts, got %+v", *got)
	}
}

func arp(ip string, mac byte) capture.Packet {
	return capture.Packet{ARP: true, ARPOp: 2, Src: netip.MustParseAddr(ip), ARPMAC: [6]byte{2, 0, 0, 0, 0, mac}}
}

func TestARPConflict(t *testing.T) {
	cfg := Defaults()
	emit, got := collect()
	d := NewARPDetector(func() *Config { return cfg }, emit)
	t0 := time.Now()
	d.ObserveAt(arp("192.168.1.1", 1), t0)
	d.ObserveAt(arp("192.168.1.1", 1), t0.Add(5*time.Second)) // same device again: fine
	if len(*got) != 0 {
		t.Fatal("same device must not alert")
	}
	d.ObserveAt(arp("192.168.1.1", 2), t0.Add(10*time.Second)) // another device claims it
	if len(*got) != 1 || (*got)[0].Rule != "arp_spoofing" {
		t.Fatalf("expected one arp_spoofing alert, got %+v", *got)
	}
	d.ObserveAt(arp("192.168.1.1", 1), t0.Add(10*time.Minute)) // long afterwards: not a conflict
	if len(*got) != 1 {
		t.Fatal("old claim must not alert")
	}
}

func TestBandwidthSpike(t *testing.T) {
	cfg := Defaults()
	emit, got := collect()
	d := NewBandwidthDetector(func() *Config { return cfg }, emit)
	mb := uint64(1024 * 1024)
	for i := 0; i < 12; i++ { // a quiet device, 1 MB a minute
		d.Minute([]MinuteUsage{{IP: "192.168.1.20", Sent: mb / 2, Recv: mb / 2}})
	}
	d.Minute([]MinuteUsage{{IP: "192.168.1.20", Sent: 10 * mb, Recv: 0}}) // 10 MB: below the 50 MB floor
	if len(*got) != 0 {
		t.Fatal("a small burst must not alert")
	}
	d.Minute([]MinuteUsage{{IP: "192.168.1.20", Sent: 150 * mb, Recv: 10 * mb}})
	if len(*got) != 1 || (*got)[0].Rule != "bandwidth_spike" {
		t.Fatalf("expected a bandwidth alert, got %+v", *got)
	}
}

func TestLogRulesCountPerAddress(t *testing.T) {
	cfg := Defaults()
	if len(cfg.LogRules) < 2 || cfg.LogRules[0].Name != "login_failures" {
		t.Fatalf("default log rules not loaded: %+v", cfg.LogRules)
	}
	emit, got := collect()
	m := NewLogMatcher(func() *Config { return cfg }, emit)
	now := time.Now()
	bad := "Failed password for root from %s port 4444 ssh2"
	for i := 0; i < 4; i++ { // four failures from each of two addresses: below the limit of 5
		m.Observe("kali", "10.0.0.9", "sshd", sprintf(bad, "203.0.113.50"), now.Add(time.Duration(i)*time.Second))
		m.Observe("kali", "10.0.0.9", "sshd", sprintf(bad, "203.0.113.51"), now.Add(time.Duration(i)*time.Second))
	}
	if len(*got) != 0 {
		t.Fatalf("the addresses must be counted separately, got %+v", *got)
	}
	m.Observe("kali", "10.0.0.9", "sshd", sprintf(bad, "203.0.113.50"), now.Add(5*time.Second))
	if len(*got) != 1 || (*got)[0].Label != "log:login_failures" || (*got)[0].Severity != "high" ||
		(*got)[0].IP != "203.0.113.50" {
		t.Fatalf("expected one login_failures alert, got %+v", *got)
	}
	m.Observe("router", "10.0.0.1", "kernel", "Kernel panic - not syncing", now) // threshold 1
	if len(*got) != 2 || (*got)[1].Label != "log:system_trouble" {
		t.Fatalf("expected a system_trouble alert, got %+v", *got)
	}
}

func TestBadLogRuleIsSkipped(t *testing.T) {
	c := Defaults()
	c.LogRules = append(c.LogRules, LogRule{Name: "broken", Match: "([unclosed", Severity: "high"})
	warns := c.normalize()
	if len(warns) == 0 {
		t.Fatal("an invalid pattern must produce a warning")
	}
	for _, r := range c.LogRules {
		if r.Name == "broken" {
			t.Fatal("the invalid rule must be removed")
		}
	}
}

func sprintf(format string, a ...any) string { return fmt.Sprintf(format, a...) }
