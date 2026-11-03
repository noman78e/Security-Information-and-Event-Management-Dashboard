package rules

import (
	"fmt"
	"regexp"
	"sync"
	"time"
)

var ipFinder = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

type compiledLog struct {
	LogRule
	re *regexp.Regexp
}

// LogMatcher checks every received log message against the log_rules in rules.yaml.
type LogMatcher struct {
	mu       sync.Mutex
	cfg      func() *Config
	emit     func(Alert)
	built    *Config
	compiled []compiledLog
	hits     map[string][]time.Time
	quiet    map[string]time.Time
}

func NewLogMatcher(cfg func() *Config, emit func(Alert)) *LogMatcher {
	return &LogMatcher{cfg: cfg, emit: emit, hits: map[string][]time.Time{}, quiet: map[string]time.Time{}}
}

func (m *LogMatcher) rebuild(c *Config) {
	m.built = c
	m.compiled = nil
	for _, r := range c.LogRules {
		if re, err := regexp.Compile("(?i)" + r.Match); err == nil {
			m.compiled = append(m.compiled, compiledLog{LogRule: r, re: re})
		}
	}
	m.hits = map[string][]time.Time{} // new rules start counting from zero
}

func shorten(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// Observe checks one message. Matching uses "program text" so rules can name the program.
func (m *LogMatcher) Observe(host, srcIP, program, text string, now time.Time) {
	c := m.cfg()
	if !c.Rules.LogMatch.Enabled || len(c.LogRules) == 0 {
		return
	}
	var out []Alert
	m.mu.Lock()
	if m.built != c {
		m.rebuild(c)
	}
	line := text
	if program != "" {
		line = program + " " + text
	}
	for _, r := range m.compiled {
		if !r.re.MatchString(line) {
			continue
		}
		group, ip, about := host, srcIP, "the machine "+host
		if group == "" {
			group = srcIP
		}
		if r.GroupBy == "ip" {
			if f := ipFinder.FindString(text); f != "" {
				group, ip, about = f, f, "the address "+f
			}
		}
		key := r.Name + "|" + group
		count := 1
		if r.Threshold > 1 {
			cut := now.Add(-time.Duration(r.WithinSeconds) * time.Second)
			kept := m.hits[key][:0]
			for _, t := range m.hits[key] {
				if t.After(cut) {
					kept = append(kept, t)
				}
			}
			kept = append(kept, now)
			if len(kept) < r.Threshold {
				if len(m.hits) < 4096 || m.hits[key] != nil {
					m.hits[key] = kept
				}
				continue
			}
			count = len(kept)
			delete(m.hits, key)
		}
		if r.CooldownMin > 0 {
			if last, ok := m.quiet[key]; ok && now.Sub(last) < time.Duration(r.CooldownMin)*time.Minute {
				continue
			}
			if len(m.quiet) > 4096 {
				for k, t := range m.quiet {
					if now.Sub(t) > time.Hour {
						delete(m.quiet, k)
					}
				}
			}
			m.quiet[key] = now
		}
		out = append(out, Alert{Rule: "log_match", Label: "log:" + r.Name, Severity: r.Severity,
			Key: key, IP: ip,
			Message: fmt.Sprintf("Log rule %q: %d matching message(s) within %d seconds about %s. Last message: %s",
				r.Name, count, r.WithinSeconds, about, shorten(line, 200))})
	}
	m.mu.Unlock()
	for _, a := range out {
		m.emit(a)
	}
}
