// Package rules holds the alert rules: the YAML settings, the detectors
// that watch traffic, and the notification senders.
package rules

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultYAML is the built-in rules file. It is written to disk on first start.
//
//go:embed default_rules.yaml
var DefaultYAML []byte

// Common settings shared by every rule.
type Common struct {
	Enabled     bool   `yaml:"enabled"`
	Severity    string `yaml:"severity"`
	CooldownMin int    `yaml:"cooldown_minutes"`
	Notify      bool   `yaml:"notify"`
}

type RiskyPortRule struct {
	Common `yaml:",inline"`
	Ports  []int `yaml:"ports"`
}

type PortScanRule struct {
	Common        `yaml:",inline"`
	WindowSeconds int      `yaml:"window_seconds"`
	PortThreshold int      `yaml:"port_threshold"`
	HostThreshold int      `yaml:"host_threshold"`
	IgnoreSelf    bool     `yaml:"ignore_self"`
	IgnoreSources []string `yaml:"ignore_sources"`
}

type BandwidthRule struct {
	Common         `yaml:",inline"`
	MinMBPerMinute int     `yaml:"min_mb_per_minute"`
	Factor         float64 `yaml:"factor"`
	WarmupMinutes  int     `yaml:"warmup_minutes"`
}

type NewDestRule struct {
	Common        `yaml:",inline"`
	LearningHours int      `yaml:"learning_hours"`
	IgnorePorts   []int    `yaml:"ignore_ports"`
	StrictDevices []string `yaml:"strict_devices"`
}

type ARPRule struct {
	Common          `yaml:",inline"`
	ConflictSeconds int `yaml:"conflict_seconds"`
}

// LogRule turns received log messages into alerts.
type LogRule struct {
	Name          string `yaml:"name"`
	Match         string `yaml:"match"`          // words or a regular expression, not case sensitive
	Severity      string `yaml:"severity"`       // low | medium | high
	Threshold     int    `yaml:"threshold"`      // matching messages needed (1 = every match alerts)
	WithinSeconds int    `yaml:"within_seconds"` // ... inside this time
	GroupBy       string `yaml:"group_by"`       // ip = count per address found in the message, host = per sending machine
	CooldownMin   int    `yaml:"cooldown_minutes"`
}

type RuleSet struct {
	LoginLockout   Common        `yaml:"login_lockout"`
	LogMatch       Common        `yaml:"log_match"`
	NewDevice      Common        `yaml:"new_device"`
	RiskyPort      RiskyPortRule `yaml:"risky_port"`
	NewOpenPort    Common        `yaml:"new_open_port"`
	PortScan       PortScanRule  `yaml:"port_scan"`
	Bandwidth      BandwidthRule `yaml:"bandwidth_spike"`
	NewDestination NewDestRule   `yaml:"new_destination"`
	ARPSpoof       ARPRule       `yaml:"arp_spoofing"`
}

type TelegramCfg struct {
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}
type WebhookCfg struct {
	URL string `yaml:"url"`
}
type EmailCfg struct {
	SMTPHost string `yaml:"smtp_host"`
	SMTPPort int    `yaml:"smtp_port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	To       string `yaml:"to"`
}
type NotifyCfg struct {
	MinSeverity string      `yaml:"min_severity"`
	Telegram    TelegramCfg `yaml:"telegram"`
	Webhook     WebhookCfg  `yaml:"webhook"`
	Email       EmailCfg    `yaml:"email"`
}

// Config is the whole rules file.
type Config struct {
	Notify   NotifyCfg `yaml:"notify"`
	Rules    RuleSet   `yaml:"rules"`
	LogRules []LogRule `yaml:"log_rules"`
}

// RuleNames lists every rule, in display order.
func RuleNames() []string {
	return []string{"new_device", "risky_port", "new_open_port", "port_scan",
		"bandwidth_spike", "new_destination", "arp_spoofing", "log_match", "login_lockout"}
}

// Lookup returns the common settings of a rule, or nil if the name is unknown.
func (r *RuleSet) Lookup(name string) *Common {
	switch name {
	case "new_device":
		return &r.NewDevice
	case "risky_port":
		return &r.RiskyPort.Common
	case "new_open_port":
		return &r.NewOpenPort
	case "port_scan":
		return &r.PortScan.Common
	case "bandwidth_spike":
		return &r.Bandwidth.Common
	case "new_destination":
		return &r.NewDestination.Common
	case "arp_spoofing":
		return &r.ARPSpoof.Common
	case "log_match":
		return &r.LogMatch
	case "login_lockout":
		return &r.LoginLockout
	}
	return nil
}

// SeverityRank turns low/medium/high into 1/2/3 (0 = invalid).
func SeverityRank(s string) int {
	switch s {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	}
	return 0
}

// IsRiskyPort reports whether a port is in the risky_port list.
func (c *Config) IsRiskyPort(port int) bool {
	for _, p := range c.Rules.RiskyPort.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// Defaults returns the built-in rules. Decoding is lenient on purpose: this
// can never stop the program from starting.
func Defaults() *Config {
	c := &Config{}
	_ = yaml.NewDecoder(bytes.NewReader(DefaultYAML)).Decode(c)
	c.normalize()
	return c
}

// Load reads a rules file on top of the defaults. Unknown keys are errors,
// so a typo in the file is reported instead of silently ignored.
func Load(path string) (*Config, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	cfg := Defaults()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, cfg.normalize(), nil
}

// LoadOrCreate writes the default file if it does not exist yet, then loads it.
func LoadOrCreate(path string) (*Config, []string, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		// 0600: the file may later hold passwords and tokens
		if err := os.WriteFile(path, DefaultYAML, 0o600); err != nil {
			return nil, nil, fmt.Errorf("cannot create %s: %w", path, err)
		}
	}
	return Load(path)
}

// normalize fixes impossible values and returns warnings about them.
func (c *Config) normalize() []string {
	var w []string
	for _, name := range RuleNames() {
		cm := c.Rules.Lookup(name)
		cm.Severity = strings.ToLower(strings.TrimSpace(cm.Severity))
		if SeverityRank(cm.Severity) == 0 {
			w = append(w, fmt.Sprintf("rule %s: severity must be low, medium or high; using medium", name))
			cm.Severity = "medium"
		}
		if cm.CooldownMin < 0 {
			cm.CooldownMin = 0
		}
	}
	c.Notify.MinSeverity = strings.ToLower(strings.TrimSpace(c.Notify.MinSeverity))
	if SeverityRank(c.Notify.MinSeverity) == 0 {
		w = append(w, "notify.min_severity must be low, medium or high; using high")
		c.Notify.MinSeverity = "high"
	}
	ps := &c.Rules.PortScan
	if ps.WindowSeconds < 1 {
		ps.WindowSeconds = 10
	}
	if ps.PortThreshold < 3 {
		ps.PortThreshold = 20
	}
	if ps.HostThreshold < 3 {
		ps.HostThreshold = 30
	}
	bw := &c.Rules.Bandwidth
	if bw.MinMBPerMinute < 1 {
		bw.MinMBPerMinute = 50
	}
	if bw.Factor < 1.5 {
		bw.Factor = 5
	}
	if bw.WarmupMinutes < 1 {
		bw.WarmupMinutes = 10
	}
	if c.Rules.NewDestination.LearningHours < 0 {
		c.Rules.NewDestination.LearningHours = 24
	}
	if c.Rules.ARPSpoof.ConflictSeconds < 1 {
		c.Rules.ARPSpoof.ConflictSeconds = 60
	}

	var keep []LogRule
	for i, lr := range c.LogRules {
		if len(keep) >= 50 {
			w = append(w, "log_rules: only the first 50 rules are used")
			break
		}
		lr.Name = strings.TrimSpace(lr.Name)
		if lr.Name == "" {
			lr.Name = fmt.Sprintf("log_rule_%d", i+1)
		}
		if strings.TrimSpace(lr.Match) == "" {
			w = append(w, fmt.Sprintf("log rule %s: match is empty, rule skipped", lr.Name))
			continue
		}
		if _, err := regexp.Compile("(?i)" + lr.Match); err != nil {
			w = append(w, fmt.Sprintf("log rule %s: the pattern is not valid (%v), rule skipped", lr.Name, err))
			continue
		}
		lr.Severity = strings.ToLower(strings.TrimSpace(lr.Severity))
		if SeverityRank(lr.Severity) == 0 {
			w = append(w, fmt.Sprintf("log rule %s: severity must be low, medium or high; using medium", lr.Name))
			lr.Severity = "medium"
		}
		if lr.Threshold < 1 {
			lr.Threshold = 1
		}
		if lr.Threshold > 1000 {
			lr.Threshold = 1000
		}
		if lr.WithinSeconds < 1 {
			lr.WithinSeconds = 60
		}
		lr.GroupBy = strings.ToLower(strings.TrimSpace(lr.GroupBy))
		if lr.GroupBy != "ip" {
			lr.GroupBy = "host"
		}
		if lr.CooldownMin < 0 {
			lr.CooldownMin = 0
		}
		keep = append(keep, lr)
	}
	c.LogRules = keep
	return w
}
