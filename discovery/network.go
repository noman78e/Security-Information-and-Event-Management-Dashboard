// Package discovery finds devices on the local network without needing
// administrator rights and without any C libraries (works on Windows,
// Linux, macOS and Raspberry Pi).
//
// How it works: we send a tiny UDP packet and a TCP connection attempt to
// every address in the subnet (20 at a time). To send them, the operating
// system must first ask "who has this IP?" using ARP. Every real device
// answers, and the OS remembers the answer in its ARP table. We then read
// that table to get the IP -> MAC address list.
package discovery

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// Network describes the subnet we scan.
type Network struct {
	IfaceName string
	IP        net.IP // our own IPv4 address
	MAC       string // our own MAC address (normalized)
	IPNet     *net.IPNet
}

func (n *Network) String() string {
	return n.IPNet.String() + " via " + n.IfaceName
}

// LocalNetwork picks the network to scan. If ifaceName is empty, it uses the
// interface that carries your default route (the one you use for internet).
func LocalNetwork(ifaceName string) (*Network, error) {
	var preferred net.IP
	if ifaceName == "" {
		// Connecting a UDP socket sends no packets; it only asks the OS
		// which local address it would use to reach the internet.
		if c, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
			if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
				preferred = ua.IP
			}
			c.Close()
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var fallback *Network
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifaceName != "" && !strings.EqualFold(ifc.Name, ifaceName) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil || ip4.IsLinkLocalUnicast() {
				continue
			}
			mask := ipn.Mask
			if len(mask) == 16 {
				mask = mask[12:]
			}
			if ones, _ := mask.Size(); ones > 30 || ones == 0 {
				continue // VPN point-to-point or invalid
			}
			n := &Network{
				IfaceName: ifc.Name,
				IP:        ip4,
				MAC:       NormMAC(ifc.HardwareAddr.String()),
				IPNet:     &net.IPNet{IP: ip4.Mask(mask), Mask: mask},
			}
			if ifaceName != "" || (preferred != nil && ip4.Equal(preferred)) {
				return n.limit(), nil
			}
			if fallback == nil && ip4.IsPrivate() {
				fallback = n
			}
		}
	}
	if fallback != nil {
		return fallback.limit(), nil
	}
	return nil, errors.New("no usable IPv4 network interface found (are you connected to a network?)")
}

// limit shrinks huge subnets (bigger than /22) to the /24 around our address,
// so a scan never takes forever on a low-power device.
func (n *Network) limit() *Network {
	if ones, _ := n.IPNet.Mask.Size(); ones < 22 {
		m := net.CIDRMask(24, 32)
		n.IPNet = &net.IPNet{IP: n.IP.Mask(m), Mask: m}
	}
	return n
}

// Hosts lists every usable address in the subnet except our own.
func (n *Network) Hosts() []net.IP {
	base := binary.BigEndian.Uint32(n.IPNet.IP.To4())
	ones, bits := n.IPNet.Mask.Size()
	size := uint32(1) << uint(bits-ones)
	out := make([]net.IP, 0, size)
	for i := uint32(1); i < size-1; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base+i)
		if ip.Equal(n.IP) {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// IPKey converts an IPv4 string to a number, for sorting.
func IPKey(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}
