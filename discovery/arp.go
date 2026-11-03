package discovery

import (
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

var (
	ipRe  = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	macRe = regexp.MustCompile(`\b([0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})\b`)
)

// NormMAC turns any MAC notation (aa-bb-.., a:b:.. without zero padding)
// into upper-case AA:BB:CC:DD:EE:FF. Returns "" if invalid.
func NormMAC(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ':' || r == '-' })
	if len(parts) != 6 {
		return ""
	}
	for i, p := range parts {
		if len(p) == 1 {
			p = "0" + p
		}
		parts[i] = p
	}
	hw, err := net.ParseMAC(strings.Join(parts, ":"))
	if err != nil || len(hw) != 6 {
		return ""
	}
	return strings.ToUpper(hw.String())
}

// usableMAC rejects empty, broadcast and multicast addresses.
func usableMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return false
	}
	if hw[0]&1 == 1 { // multicast / broadcast
		return false
	}
	for _, b := range hw {
		if b != 0 {
			return true
		}
	}
	return false // all zeros = incomplete ARP entry
}

// ReadARP returns the operating system's ARP table as IP -> MAC.
func ReadARP() map[string]string {
	text := ""
	if runtime.GOOS == "linux" {
		// Present on every Linux, including Raspberry Pi OS, no tools needed.
		if b, err := os.ReadFile("/proc/net/arp"); err == nil {
			text = string(b)
		}
	}
	if text == "" {
		if out, err := exec.Command("arp", "-a").Output(); err == nil {
			text = string(out)
		}
	}
	return parseARP(text)
}

// parseARP understands the output of Linux (/proc/net/arp), Windows
// (arp -a) and macOS (arp -a).
func parseARP(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		ip := ipRe.FindString(line)
		m := macRe.FindString(line)
		if ip == "" || m == "" {
			continue
		}
		mac := NormMAC(m)
		if mac == "" || !usableMAC(mac) {
			continue
		}
		out[ip] = mac
	}
	return out
}
