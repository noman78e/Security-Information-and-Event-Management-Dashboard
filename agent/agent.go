// Package agent is the small log forwarder: it follows log files on a
// computer and sends every new line to HomeSIEM as syslog. It is part of the
// same program, started with "homesiem agent ...", so you can copy the one
// file to any Linux, Windows, macOS or Raspberry Pi machine.
package agent

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type fileList []string

func (f *fileList) String() string     { return strings.Join(*f, ",") }
func (f *fileList) Set(v string) error { *f = append(*f, v); return nil }

// looksSyslog recognises lines that already start like a syslog line
// ("Oct 28 12:00:01 host ..." or "2026-10-28T12:00:01 host ..."), which
// are forwarded as they are so the program name and host stay correct.
var looksSyslog = regexp.MustCompile(`^([A-Z][a-z]{2} [ 0-9][0-9] \d\d:\d\d:\d\d |\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)`)

// BuildMessage wraps a plain log line into a syslog message (facility local0).
func BuildMessage(line, host, tag string, severity int, now time.Time) string {
	pri := 16*8 + severity
	if looksSyslog.MatchString(line) {
		return fmt.Sprintf("<%d>%s", pri, line)
	}
	return fmt.Sprintf("<%d>%s %s %s: %s", pri, now.Format("Jan _2 15:04:05"), host, tag, line)
}

type sender struct {
	mu     sync.Mutex
	proto  string
	server string
	conn   net.Conn
}

func (s *sender) send(msg string) error {
	if s.proto == "udp" && len(msg) > 1400 {
		msg = msg[:1400]
	}
	if s.proto == "tcp" {
		msg += "\n"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if s.conn == nil {
			c, err := net.DialTimeout(s.proto, s.server, 5*time.Second)
			if err != nil {
				return err
			}
			s.conn = c
		}
		s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := s.conn.Write([]byte(msg)); err != nil {
			s.conn.Close()
			s.conn = nil
			continue // reconnect once and try again
		}
		return nil
	}
	return fmt.Errorf("could not send to %s", s.server)
}

// follow watches one file and calls emit for every new line. It survives
// log rotation (a new file appearing) and truncation.
func follow(path string, fromStart bool, emit func(string), stop <-chan struct{}) {
	_, statErr := os.Stat(path)
	startAtEnd := !fromStart && statErr == nil
	var f *os.File
	var fi os.FileInfo
	var off int64
	var partial []byte
	buf := make([]byte, 64*1024)
	warned := false
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			if f != nil {
				f.Close()
			}
			return
		case <-t.C:
		}
		cur, err := os.Stat(path)
		if err != nil { // file missing: wait for it to appear
			if f != nil {
				f.Close()
				f = nil
			}
			continue
		}
		if f != nil && fi != nil && !os.SameFile(fi, cur) { // rotated: the old file was replaced
			f.Close()
			f, off, partial = nil, 0, nil
		}
		if f == nil {
			nf, err := os.Open(path)
			if err != nil {
				if !warned {
					log.Printf("cannot open %s: %v (is the program allowed to read it? try sudo)", path, err)
					warned = true
				}
				continue
			}
			warned = false
			f = nf
			fi, _ = f.Stat()
			off = 0
			if startAtEnd {
				off = cur.Size()
			}
			startAtEnd = false
			log.Printf("following %s", path)
		}
		if cur.Size() < off { // truncated
			off, partial = 0, nil
		}
		for {
			n, _ := f.ReadAt(buf, off)
			if n <= 0 {
				break
			}
			off += int64(n)
			partial = append(partial, buf[:n]...)
			for {
				i := bytes.IndexByte(partial, '\n')
				if i < 0 {
					break
				}
				line := strings.TrimRight(string(partial[:i]), "\r")
				partial = partial[i+1:]
				if strings.TrimSpace(line) != "" {
					emit(line)
				}
			}
			if len(partial) > 1<<20 { // a "line" over 1 MB without a newline: give up on it
				partial = nil
			}
		}
	}
}

// Run is the entry point of "homesiem agent".
func Run(args []string) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	var files fileList
	fs.Var(&files, "file", "log file to send (repeat the flag for several files)")
	server := fs.String("server", "", "HomeSIEM address and port, for example 192.168.1.16:514")
	proto := fs.String("proto", "udp", "udp or tcp")
	name := fs.String("name", hostname, "the name this computer uses in the logs")
	fromStart := fs.Bool("from-start", false, "send the whole file first, not only new lines")
	sev := fs.Int("severity", 6, "syslog severity for lines that have none (0 emergency ... 7 debug)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "HomeSIEM log agent: sends new lines of log files to HomeSIEM.")
		fmt.Fprintln(os.Stderr, "\nExample:\n  homesiem agent -server 192.168.1.16:514 -file /var/log/auth.log -file /var/log/syslog")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if *server == "" || len(files) == 0 || (*proto != "udp" && *proto != "tcp") || *sev < 0 || *sev > 7 {
		fs.Usage()
		os.Exit(2)
	}
	host := strings.ReplaceAll(strings.TrimSpace(*name), " ", "-")
	snd := &sender{proto: *proto, server: *server}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, p := range files {
		p := p
		tag := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
		wg.Add(1)
		go func() {
			defer wg.Done()
			follow(p, *fromStart, func(line string) {
				if err := snd.send(BuildMessage(line, host, tag, *sev, time.Now())); err != nil {
					log.Printf("send failed: %v", err)
					time.Sleep(time.Second)
				}
			}, stop)
		}()
	}
	log.Printf("agent started: sending %d file(s) to %s over %s as %q", len(files), *server, *proto, host)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	close(stop)
	wg.Wait()
}
