package portscan

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

var tlsPorts = map[int]bool{443: true, 465: true, 636: true, 993: true, 995: true, 8443: true, 8883: true}
var httpPorts = map[int]bool{80: true, 81: true, 3000: true, 5000: true, 8000: true, 8008: true,
	8080: true, 8081: true, 8123: true, 8888: true, 9090: true, 10000: true}
var rtspPorts = map[int]bool{554: true, 8554: true}

// grabBanner talks to an open port just enough to learn what is running.
// Everything it returns comes from the remote device, so it is cleaned to
// plain printable text and shortened. The dashboard also shows it as text only.
func grabBanner(conn net.Conn, ip string, port int) string {
	conn.SetDeadline(time.Now().Add(600 * time.Millisecond))
	switch {
	case tlsPorts[port]:
		return tlsInfo(conn)
	case httpPorts[port]:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: HomeSIEM\r\nConnection: close\r\n\r\n", ip)
		return headerInfo(readHeaders(conn))
	case rtspPorts[port]:
		fmt.Fprintf(conn, "OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: HomeSIEM\r\n\r\n", ip)
		return headerInfo(readHeaders(conn))
	default:
		// Many services (ssh, ftp, smtp, mysql...) announce themselves first.
		return clean(firstLine(readOnce(conn)), 120)
	}
}

func readOnce(conn net.Conn) string {
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

func readHeaders(conn net.Conn) string {
	var sb strings.Builder
	buf := make([]byte, 1024)
	for sb.Len() < 4096 {
		n, err := conn.Read(buf)
		sb.Write(buf[:n])
		if err != nil || strings.Contains(sb.String(), "\r\n\r\n") {
			break
		}
	}
	return sb.String()
}

func headerInfo(resp string) string {
	if resp == "" {
		return ""
	}
	lines := strings.Split(resp, "\n")
	first := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(first, "HTTP/") && !strings.HasPrefix(first, "RTSP/") {
		return clean(first, 120)
	}
	var parts []string
	if f := strings.Fields(first); len(f) >= 2 {
		parts = append(parts, strings.SplitN(f[0], "/", 2)[0]+" "+f[1])
	}
	for _, l := range lines[1:] {
		l = strings.TrimSpace(l)
		low := strings.ToLower(l)
		if strings.HasPrefix(low, "server:") {
			parts = append(parts, "Server: "+strings.TrimSpace(l[7:]))
		} else if strings.HasPrefix(low, "www-authenticate:") {
			parts = append(parts, "Auth: "+strings.TrimSpace(l[17:]))
		}
	}
	return clean(strings.Join(parts, ", "), 160)
}

// tlsInfo reads the TLS version and certificate name. It deliberately does
// not verify the certificate: we are inspecting the device, not trusting it.
func tlsInfo(conn net.Conn) string {
	conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
	if err := tc.Handshake(); err != nil {
		return ""
	}
	st := tc.ConnectionState()
	s := "TLS " + tls.VersionName(st.Version)
	if len(st.PeerCertificates) > 0 {
		if cn := st.PeerCertificates[0].Subject.CommonName; cn != "" {
			s += ", CN=" + cn
		}
	}
	return clean(s, 120)
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// clean keeps printable ASCII only and limits the length.
func clean(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > max {
		out = out[:max]
	}
	return out
}
