package logcollect

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

func parse(t *testing.T, raw string) Message {
	t.Helper()
	m, ok := Parse(raw, "10.0.0.9", time.Now())
	if !ok {
		t.Fatalf("message was rejected: %q", raw)
	}
	return m
}

func TestParseClassicSyslog(t *testing.T) {
	m := parse(t, "<38>Oct 28 12:34:56 kali sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2")
	if m.Facility != 4 || m.Severity != 6 || m.Host != "kali" || m.Program != "sshd" ||
		m.Text != "Failed password for root from 10.0.0.5 port 22 ssh2" {
		t.Fatalf("wrong parse: %+v", m)
	}
}

func TestParseRFC5424(t *testing.T) {
	m := parse(t, `<165>1 2026-10-28T12:34:56.003Z router.lan dnsmasq 321 ID47 [exampleSDID@32473 iut="3" eventSource="App]lication"] DHCPACK 192.168.1.20`)
	if m.Facility != 20 || m.Severity != 5 || m.Host != "router.lan" || m.Program != "dnsmasq" || m.Text != "DHCPACK 192.168.1.20" {
		t.Fatalf("wrong parse: %+v", m)
	}
}

func TestParseWithoutHostName(t *testing.T) {
	m := parse(t, "<13>Oct  7 08:01:02 cron[12]: (root) CMD (run-parts)")
	if m.Host != "10.0.0.9" || m.Program != "cron" || m.Text != "(root) CMD (run-parts)" {
		t.Fatalf("wrong parse: %+v", m)
	}
}

func TestParseISOTimestamp(t *testing.T) {
	m := parse(t, "<86>2026-10-28T12:34:56.123456+05:00 kali sudo: pam_unix(sudo:session): session opened")
	if m.Host != "kali" || m.Program != "sudo" || m.Text != "pam_unix(sudo:session): session opened" {
		t.Fatalf("wrong parse: %+v", m)
	}
}

func TestParsePlainText(t *testing.T) {
	m := parse(t, "Link is down on port 3")
	if m.Host != "10.0.0.9" || m.Program != "" || m.Text != "Link is down on port 3" || m.Severity != 6 {
		t.Fatalf("wrong parse: %+v", m)
	}
}

func TestParseCleansUntrustedText(t *testing.T) {
	m := parse(t, "<14>Oct 28 12:00:00 evil app: hello\x00\x1b[31mred\nline"+strings.Repeat("x", 5000))
	if strings.ContainsAny(m.Text, "\x00\x1b\n") {
		t.Fatalf("control characters survived: %q", m.Text)
	}
	if len(m.Text) > 2000 {
		t.Fatalf("message not shortened: %d bytes", len(m.Text))
	}
	if _, ok := Parse("   \r\n", "10.0.0.9", time.Now()); ok {
		t.Fatal("an empty message must be rejected")
	}
}

func TestTCPFraming(t *testing.T) {
	in := "13 <34>hello xyz" + "<14>second line\n" + "<14>third line\r\n"
	r := bufio.NewReader(strings.NewReader(in))
	for _, want := range []string{"<34>hello xyz", "<14>second line", "<14>third line"} {
		got, err := readFrame(r)
		if err != nil || got != want {
			t.Fatalf("got %q (%v), want %q", got, err, want)
		}
	}
}
