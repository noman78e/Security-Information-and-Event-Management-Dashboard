package logcollect

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Server receives syslog over UDP and TCP on the same port.
type Server struct {
	Addr      string
	Allow     func(netip.Addr) bool // nil = accept everyone
	Sink      func(Message)
	Rate      float64 // messages per second allowed from one sender
	Listening []string

	udp     net.PacketConn
	conns   chan struct{}
	mu      sync.Mutex
	buckets map[netip.Addr]*bucket

	Received atomic.Uint64
	Dropped  atomic.Uint64
}

func NewServer(addr string, allow func(netip.Addr) bool, sink func(Message), rate float64) *Server {
	if rate <= 0 {
		rate = 200
	}
	return &Server{Addr: addr, Allow: allow, Sink: sink, Rate: rate,
		conns: make(chan struct{}, 64), buckets: map[netip.Addr]*bucket{}}
}

// Start begins listening. Port 514 needs administrator rights on Linux, so
// if it is refused the server falls back to port 5514.
func (s *Server) Start() error {
	err := s.listen(s.Addr)
	if err == nil {
		return nil
	}
	if host, port, e := net.SplitHostPort(s.Addr); e == nil && port == "514" {
		if err2 := s.listen(net.JoinHostPort(host, "5514")); err2 == nil {
			log.Printf("syslog: port 514 not allowed (%v), using 5514 instead", err)
			return nil
		}
	}
	return err
}

func (s *Server) listen(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	s.udp = pc
	s.Listening = append(s.Listening, "udp "+pc.LocalAddr().String())
	go s.udpLoop()
	if ln, err := net.Listen("tcp", addr); err == nil {
		s.Listening = append(s.Listening, "tcp "+ln.Addr().String())
		go s.tcpLoop(ln)
	} else {
		log.Printf("syslog: tcp %s not available: %v", addr, err)
	}
	return nil
}

// UDPPort returns the port the UDP listener really uses.
func (s *Server) UDPPort() string {
	if s.udp == nil {
		return ""
	}
	_, port, _ := net.SplitHostPort(s.udp.LocalAddr().String())
	return port
}

// take is a per-sender rate limit, so one noisy device cannot flood the database.
func (s *Server) take(ip netip.Addr, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	burst := s.Rate * 2
	b := s.buckets[ip]
	if b == nil {
		if len(s.buckets) >= 1500 {
			for k, v := range s.buckets { // forget senders idle for 10 minutes
				if now.Sub(v.last) > 10*time.Minute {
					delete(s.buckets, k)
				}
			}
			if len(s.buckets) >= 2048 {
				return false
			}
		}
		b = &bucket{tokens: burst, last: now}
		s.buckets[ip] = b
	}
	b.tokens = math.Min(burst, b.tokens+now.Sub(b.last).Seconds()*s.Rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (s *Server) handle(raw string, ip netip.Addr) {
	s.Received.Add(1)
	now := time.Now()
	if s.Allow != nil && !s.Allow(ip) {
		s.Dropped.Add(1)
		return
	}
	if !s.take(ip, now) {
		s.Dropped.Add(1)
		return
	}
	if m, ok := Parse(raw, ip.String(), now); ok {
		s.Sink(m)
	}
}

func (s *Server) udpLoop() {
	buf := make([]byte, 65536)
	for {
		n, from, err := s.udp.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ua.IP)
		if !ok {
			continue
		}
		s.handle(string(buf[:n]), ip.Unmap())
	}
}

func (s *Server) tcpLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case s.conns <- struct{}{}:
			go func() {
				defer func() { <-s.conns }()
				s.serveConn(c)
			}()
		default:
			c.Close() // too many connections at once
		}
	}
}

func (s *Server) serveConn(c net.Conn) {
	defer c.Close()
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return
	}
	ip = ip.Unmap()
	if s.Allow != nil && !s.Allow(ip) {
		s.Dropped.Add(1)
		return
	}
	r := bufio.NewReaderSize(c, 65536)
	for {
		c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		msg, err := readFrame(r)
		if err != nil {
			return
		}
		if msg != "" {
			s.handle(msg, ip)
		}
	}
}

// readFrame reads one message from a TCP stream. It understands both
// newline-separated messages and "length message" framing (RFC 6587).
func readFrame(r *bufio.Reader) (string, error) {
	b, err := r.Peek(1)
	if err != nil {
		return "", err
	}
	if b[0] >= '1' && b[0] <= '9' {
		n := r.Buffered()
		if n > 8 {
			n = 8
		}
		peek, _ := r.Peek(n)
		if i := bytes.IndexByte(peek, ' '); i > 0 && i <= 6 && i+1 < len(peek) && peek[i+1] == '<' {
			if size, err := strconv.Atoi(string(peek[:i])); err == nil && size > 0 && size <= 65536 {
				r.Discard(i + 1)
				buf := make([]byte, size)
				if _, err := io.ReadFull(r, buf); err != nil {
					return "", err
				}
				return string(buf), nil
			}
		}
	}
	line, isPrefix, err := r.ReadLine()
	if err != nil {
		return "", err
	}
	msg := string(line)
	for isPrefix { // throw away the rest of an absurdly long line
		_, isPrefix, err = r.ReadLine()
		if err != nil {
			break
		}
	}
	return msg, nil
}
