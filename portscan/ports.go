// Package portscan checks which TCP ports are open on a device and tries to
// identify the service behind each one. It uses plain "connect" scanning
// (a normal TCP connection), so it needs no administrator rights and works
// the same on Windows, Linux, macOS and Raspberry Pi.
package portscan

// DefaultPorts are the nmap "top 100" TCP ports plus a few that matter on
// home networks (MQTT, Android ADB, router management, cameras, Home Assistant).
var DefaultPorts = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
	79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
	139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
	465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
	646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
	1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
	2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
	5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
	6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
	9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
	// home-network extras
	1883, 2323, 5555, 7547, 8123, 8554, 8883, 9090, 37777,
}

var services = map[int]string{
	7: "echo", 9: "discard", 13: "daytime", 21: "ftp", 22: "ssh", 23: "telnet",
	25: "smtp", 26: "smtp-alt", 37: "time", 53: "dns", 79: "finger", 80: "http",
	81: "http-alt", 88: "kerberos", 110: "pop3", 111: "rpcbind", 113: "ident",
	119: "nntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 179: "bgp",
	389: "ldap", 427: "slp", 443: "https", 445: "smb", 465: "smtps",
	513: "rlogin", 514: "rsh/syslog", 515: "printer-lpd", 543: "klogin",
	544: "kshell", 548: "afp", 554: "rtsp", 587: "smtp-submission", 631: "ipp",
	646: "ldp", 873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s",
	1433: "mssql", 1720: "h323", 1723: "pptp", 1883: "mqtt", 1900: "upnp",
	2049: "nfs", 2121: "ftp-alt", 2323: "telnet-alt", 3000: "http-dev",
	3128: "proxy", 3306: "mysql", 3389: "rdp", 4899: "radmin", 5000: "upnp/http",
	5060: "sip", 5357: "wsdapi", 5432: "postgresql", 5555: "adb", 5631: "pcanywhere",
	5666: "nrpe", 5800: "vnc-http", 5900: "vnc", 6000: "x11", 7070: "realserver",
	7547: "tr-069", 8000: "http-alt", 8008: "http-alt", 8009: "ajp/cast",
	8080: "http-proxy", 8081: "http-alt", 8123: "home-assistant", 8443: "https-alt",
	8554: "rtsp-alt", 8883: "mqtt-tls", 8888: "http-alt", 9090: "http-alt",
	9100: "jetdirect", 10000: "webmin", 32768: "rpc", 37777: "dahua-dvr",
}

// ServiceName returns the usual service for a port, or "" if unknown.
// This is a guess from the port number; the banner shows what really answered.
func ServiceName(port int) string {
	if s, ok := services[port]; ok {
		return s
	}
	if port >= 49152 && port <= 49157 {
		return "dynamic-rpc"
	}
	return ""
}
