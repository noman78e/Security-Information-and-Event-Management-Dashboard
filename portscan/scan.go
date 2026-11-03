package portscan

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Result is one open port.
type Result struct {
	Port    int
	Service string
	Banner  string
}

// Options controls how hard the scan hits the network.
type Options struct {
	Timeout time.Duration // per connection attempt
	Conc    int           // ports tried at the same time on one device
	Limiter *Limiter      // shared across all devices; nil = unlimited
}

// Limiter caps how many connection attempts start per second across the
// whole program, so a scan never floods a small router or a slow CPU.
type Limiter struct {
	mu   sync.Mutex
	next time.Time
	gap  time.Duration
}

// NewLimiter allows perSec attempts per second. perSec <= 0 means no limit.
func NewLimiter(perSec int) *Limiter {
	l := &Limiter{}
	if perSec > 0 {
		l.gap = time.Second / time.Duration(perSec)
	}
	return l
}

// Wait blocks until the caller may start the next attempt.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.gap == 0 {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.gap)
	l.mu.Unlock()
	if d := time.Until(at); d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

// ScanHost connects to every port in `ports` on one device and returns the
// ones that accepted the connection, sorted by port number.
func ScanHost(ctx context.Context, ip string, ports []int, o Options) []Result {
	if o.Timeout <= 0 {
		o.Timeout = 500 * time.Millisecond
	}
	if o.Conc <= 0 {
		o.Conc = 10
	}
	jobs := make(chan int)
	var mu sync.Mutex
	var out []Result
	var wg sync.WaitGroup
	for i := 0; i < o.Conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: o.Timeout}
			for p := range jobs {
				if o.Limiter.Wait(ctx) != nil {
					return
				}
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
				if err != nil {
					continue // closed or filtered
				}
				banner := grabBanner(conn, ip, p)
				conn.Close()
				mu.Lock()
				out = append(out, Result{Port: p, Service: ServiceName(p), Banner: banner})
				mu.Unlock()
			}
		}()
	}
feed:
	for _, p := range ports {
		select {
		case jobs <- p:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}
