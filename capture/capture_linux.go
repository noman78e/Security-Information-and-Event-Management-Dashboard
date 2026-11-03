//go:build linux

package capture

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	ethPAll      = 0x0003 // every protocol
	msgTrunc     = 0x20   // return the real packet length even if it did not fit
	siocGIFFLAGS = 0x8913
	siocSIFFLAGS = 0x8914
	iffPromisc   = 0x100
)

// ifreqFlags is the Linux "ifreq" structure, sized for 32- and 64-bit systems.
type ifreqFlags struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

type rawSource struct {
	fd         int
	iface      string
	promiscSet bool // true only if WE turned promiscuous mode on
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Open starts capturing on the named interface. Needs root or the
// cap_net_raw capability.
func Open(iface string, promisc bool) (Source, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("open raw socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifc.Index}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind to %s: %w", iface, err)
	}
	// 1 MB of kernel buffering absorbs short bursts on a slow CPU.
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)
	// Wake up once a second so the program can shut down cleanly.
	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	s := &rawSource{fd: fd, iface: iface}
	if promisc {
		if err := s.setPromisc(true); err != nil {
			s.Close()
			return nil, fmt.Errorf("promiscuous mode: %w", err)
		}
	}
	return s, nil
}

func (s *rawSource) Read(buf []byte) (int, int, error) {
	n, _, err := syscall.Recvfrom(s.fd, buf, msgTrunc)
	switch err {
	case nil:
		stored := n
		if stored > len(buf) {
			stored = len(buf)
		}
		return stored, n, nil
	case syscall.EAGAIN, syscall.EINTR:
		return 0, 0, nil // timeout or signal: nothing to report
	default:
		return 0, 0, err
	}
}

func (s *rawSource) Close() error {
	if s.promiscSet {
		s.setPromisc(false) // put the interface back the way we found it
	}
	return syscall.Close(s.fd)
}

func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

func (s *rawSource) setPromisc(on bool) error {
	var r ifreqFlags
	copy(r.name[:], s.iface)
	if err := ioctl(s.fd, siocGIFFLAGS, unsafe.Pointer(&r)); err != nil {
		return err
	}
	had := r.flags&iffPromisc != 0
	switch {
	case on && !had:
		r.flags |= iffPromisc
		s.promiscSet = true
	case !on && s.promiscSet:
		r.flags &^= iffPromisc
		s.promiscSet = false
	default:
		return nil
	}
	return ioctl(s.fd, siocSIFFLAGS, unsafe.Pointer(&r))
}
