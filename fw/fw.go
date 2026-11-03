// Package fw builds and loads the firewall rules that block or slow down
// devices. It only ever touches its own nftables table called "homesiem",
// so your other firewall rules are never changed.
//
// These rules take effect only for traffic that passes THROUGH this
// computer, so it must be your network's gateway (router).
package fw

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Entry is what to do with one device.
type Entry struct {
	MAC         string // AA:BB:CC:DD:EE:FF
	IP          string // current IPv4 address, may be empty
	Block       bool
	LimitKBytes int // speed limit in kilobytes per second, 0 = none
}

var macRe = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

func validIPv4(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

// Script returns the nftables script for the given devices. Every value that
// ends up in the script is checked first (MAC and IPv4 formats, numbers), so
// nothing typed into the dashboard can inject commands.
//
// With macMatch the rules match the hardware address (which also covers IPv6
// and devices that change IP). Without it, only IPv4 addresses are used.
func Script(entries []Entry, macMatch bool) string {
	var fwd, in, notes []string
	for _, e := range entries {
		if !macRe.MatchString(e.MAC) {
			continue
		}
		mac := strings.ToUpper(e.MAC)
		ip := ""
		if validIPv4(e.IP) {
			ip = e.IP
		}
		switch {
		case e.Block:
			notes = append(notes, fmt.Sprintf("# blocked: %s %s", mac, ip))
			switch {
			case macMatch:
				fwd = append(fwd, "ether saddr "+mac+" drop")
				in = append(in, "ether saddr "+mac+" drop")
				if ip != "" {
					fwd = append(fwd, "ip daddr "+ip+" drop") // traffic coming back to it
				}
			case ip != "":
				fwd = append(fwd, "ip saddr "+ip+" drop", "ip daddr "+ip+" drop")
				in = append(in, "ip saddr "+ip+" drop")
			default:
				notes = append(notes, "# cannot block "+mac+": its IP address is unknown")
			}
		case e.LimitKBytes > 0:
			rate := e.LimitKBytes
			if rate > 10000000 {
				rate = 10000000
			}
			burst := rate / 4
			if burst < 16 {
				burst = 16
			}
			limit := fmt.Sprintf("limit rate over %d kbytes/second burst %d kbytes drop", rate, burst)
			notes = append(notes, fmt.Sprintf("# speed limit %d KB/s: %s %s", rate, mac, ip))
			switch {
			case macMatch:
				fwd = append(fwd, "ether saddr "+mac+" "+limit) // what the device sends
			case ip != "":
				fwd = append(fwd, "ip saddr "+ip+" "+limit)
			}
			if ip != "" {
				fwd = append(fwd, "ip daddr "+ip+" "+limit) // what it receives
			}
		}
	}
	var b strings.Builder
	b.WriteString("# HomeSIEM access control rules. Generated automatically, do not edit by hand.\n")
	for _, n := range notes {
		b.WriteString(n + "\n")
	}
	b.WriteString("table inet homesiem\n")
	b.WriteString("delete table inet homesiem\n")
	b.WriteString("table inet homesiem {\n")
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority -10; policy accept;\n")
	for _, r := range fwd {
		b.WriteString("\t\t" + r + "\n")
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n")
	for _, r := range in {
		b.WriteString("\t\t" + r + "\n")
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

func short(out []byte) string {
	s := strings.TrimSpace(string(out))
	if len(s) > 500 {
		s = s[:500] + "..."
	}
	return s
}

// Load applies a script atomically: either all rules are installed or none.
func Load(script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft could not apply the rules: %s", short(out))
	}
	return nil
}

// Remove deletes the HomeSIEM table, which unblocks everyone.
func Remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", "homesiem").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("nft could not remove the rules: %s", short(out))
	}
	return nil
}

// ParseGateway finds the default gateway in the text of /proc/net/route.
func ParseGateway(route string) string {
	for _, line := range strings.Split(route, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		return fmt.Sprintf("%d.%d.%d.%d", byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	return ""
}

// DefaultGateway returns your router's address (Linux only, "" if unknown).
func DefaultGateway() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil || len(b) == 0 {
		return ""
	}
	return ParseGateway(string(b))
}

// Forwarding reports whether this computer routes traffic between networks.
// If not, blocking rules cannot affect other devices.
func Forwarding() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// parseCapEff reads the CapEff line of /proc/self/status and reports whether
// the CAP_NET_ADMIN capability (bit 12) is present.
func parseCapEff(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
			return err == nil && v&(1<<12) != 0
		}
	}
	return false
}

// HasNetAdmin reports whether this program may change firewall rules even
// though it is not root (for example a systemd service started with
// AmbientCapabilities=CAP_NET_ADMIN). Linux only.
func HasNetAdmin() bool {
	b, err := os.ReadFile("/proc/self/status")
	return err == nil && parseCapEff(string(b))
}
