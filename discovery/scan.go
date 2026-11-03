package discovery

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Host is one device found on the network.
type Host struct {
	IP   string
	MAC  string
	Self bool
}

// probe pokes one address so the OS performs an ARP lookup for it.
func probe(ctx context.Context, ip string) {
	d := net.Dialer{Timeout: 300 * time.Millisecond}
	if c, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, "9")); err == nil {
		c.Write([]byte{0})
		c.Close()
	}
	if c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "80")); err == nil {
		c.Close()
	}
}

// Scan probes the whole subnet using `workers` parallel workers (default 20)
// and returns the devices that answered, sorted by IP address.
func (n *Network) Scan(ctx context.Context, workers int) []Host {
	if workers < 1 {
		workers = 20
	}
	jobs := make(chan net.IP)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				probe(ctx, ip.String())
			}
		}()
	}
feed:
	for _, ip := range n.Hosts() {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	time.Sleep(600 * time.Millisecond) // let late ARP replies arrive

	var hosts []Host
	if n.MAC != "" {
		hosts = append(hosts, Host{IP: n.IP.String(), MAC: n.MAC, Self: true})
	}
	for ip, mac := range ReadARP() {
		parsed := net.ParseIP(ip)
		if parsed == nil || !n.IPNet.Contains(parsed) || parsed.Equal(n.IP) {
			continue
		}
		hosts = append(hosts, Host{IP: ip, MAC: mac})
	}
	sort.Slice(hosts, func(i, j int) bool { return IPKey(hosts[i].IP) < IPKey(hosts[j].IP) })

	// One MAC may answer for several IPs (some routers do): keep the lowest IP.
	uniq := make([]Host, 0, len(hosts))
	used := map[string]bool{}
	for _, h := range hosts {
		if used[h.MAC] {
			continue
		}
		used[h.MAC] = true
		uniq = append(uniq, h)
	}
	return uniq
}

// ResolveName tries a reverse DNS lookup (your router often knows the names
// of devices that got an address from it). Returns "" if unknown.
func ResolveName(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
