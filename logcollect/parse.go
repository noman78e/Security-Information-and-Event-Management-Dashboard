// Package logcollect receives syslog messages from routers and other
// machines (UDP and TCP) and turns them into structured log records.
package logcollect

import (
	"strconv"
	"strings"
	"time"
)

// Message is one received log line.
type Message struct {
	Time     time.Time
	SrcIP    string // who actually sent it (cannot be faked over TCP)
	Host     string // the machine name written inside the message
	Program  string
	Facility int // 0-23
	Severity int // 0 emergency ... 7 debug
	Text     string
}

var months = map[string]bool{"Jan": true, "Feb": true, "Mar": true, "Apr": true, "May": true, "Jun": true,
	"Jul": true, "Aug": true, "Sep": true, "Oct": true, "Nov": true, "Dec": true}

func nextToken(s string) (tok, rest string) {
	s = strings.TrimLeft(s, " ")
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// tidy makes untrusted text safe to store and show: valid UTF-8, no control
// characters, limited length.
func tidy(s string, max int) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

func isTag(tok string) bool {
	return tok != "" && (strings.HasSuffix(tok, ":") || (strings.Contains(tok, "[") && strings.HasSuffix(tok, "]")))
}

func progName(tok string) string {
	tok = strings.TrimSuffix(tok, ":")
	if i := strings.IndexByte(tok, '['); i > 0 {
		tok = tok[:i]
	}
	return tok
}

func looksISO(tok string) bool {
	return len(tok) >= 19 && tok[0] >= '0' && tok[0] <= '9' && tok[4] == '-' && tok[7] == '-' && tok[10] == 'T'
}

// skipSD skips the "[...][...]" structured data block of an RFC 5424 message.
func skipSD(s string) string {
	i := 0
	for i < len(s) && s[i] == '[' {
		inQuote := false
		j := i + 1
		for ; j < len(s); j++ {
			c := s[j]
			if c == '\\' {
				j++
				continue
			}
			if c == '"' {
				inQuote = !inQuote
				continue
			}
			if c == ']' && !inQuote {
				break
			}
		}
		if j >= len(s) {
			return s // malformed: keep everything
		}
		i = j + 1
	}
	return s[i:]
}

func parse5424(m *Message, s string) {
	_, rest := nextToken(s) // timestamp (we use the time of arrival instead)
	host, rest := nextToken(rest)
	app, rest := nextToken(rest)
	_, rest = nextToken(rest) // process id
	_, rest = nextToken(rest) // message id
	rest = strings.TrimLeft(rest, " ")
	switch {
	case strings.HasPrefix(rest, "-"):
		rest = rest[1:]
	case strings.HasPrefix(rest, "["):
		rest = skipSD(rest)
	}
	rest = strings.TrimPrefix(strings.TrimLeft(rest, " "), "\xef\xbb\xbf")
	if host != "-" {
		m.Host = host
	}
	if app != "-" {
		m.Program = app
	}
	m.Text = rest
}

// parse3164 understands the classic BSD syslog format and the ISO-timestamp
// variant that modern rsyslog writes. It copes with routers that leave out
// the host name or the timestamp.
func parse3164(m *Message, s string) {
	s = strings.TrimLeft(s, " ")
	hadTS := false
	if len(s) >= 16 && months[s[:3]] && s[3] == ' ' && s[6] == ' ' && s[9] == ':' && s[12] == ':' && s[15] == ' ' {
		s, hadTS = s[16:], true
	} else if tok, rest := nextToken(s); looksISO(tok) {
		s, hadTS = rest, true
	}
	tok, rest := nextToken(s)
	if hadTS {
		if isTag(tok) { // "sshd[12]: message" (no host field)
			m.Program, m.Text = progName(tok), rest
			return
		}
		m.Host = tok
		tok2, rest2 := nextToken(rest)
		if isTag(tok2) {
			m.Program, m.Text = progName(tok2), rest2
			return
		}
		m.Text = rest
		return
	}
	if isTag(tok) {
		m.Program, m.Text = progName(tok), rest
		return
	}
	m.Text = s
}

// Parse turns one raw syslog message into a Message. It returns false if
// the message has no text.
func Parse(raw, srcIP string, now time.Time) (Message, bool) {
	m := Message{Time: now, SrcIP: srcIP, Host: srcIP, Facility: 1, Severity: 6}
	s := strings.Trim(raw, "\r\n\x00 \t")
	hadPRI := false
	if strings.HasPrefix(s, "<") {
		if i := strings.IndexByte(s, '>'); i >= 2 && i <= 4 {
			if pri, err := strconv.Atoi(s[1:i]); err == nil && pri >= 0 && pri <= 191 {
				m.Facility, m.Severity = pri/8, pri%8
				s = s[i+1:]
				hadPRI = true
			}
		}
	}
	if hadPRI && len(s) > 2 && s[0] == '1' && s[1] == ' ' {
		parse5424(&m, s[2:])
	} else {
		parse3164(&m, s)
	}
	m.Host = tidy(m.Host, 64)
	if m.Host == "" {
		m.Host = srcIP
	}
	m.Program = tidy(m.Program, 48)
	m.Text = tidy(m.Text, 2000)
	return m, m.Text != ""
}
