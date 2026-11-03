// Package capture reads packet headers from a network interface and
// summarizes them into traffic "flows" (who talked to whom, on which port,
// how many bytes). Packets themselves are never stored.
//
// Live capture uses a raw AF_PACKET socket, which needs no C library and
// no extra Go modules, so it cross-compiles for every Raspberry Pi and Linux PC.
package capture

// Source delivers packets from the network.
type Source interface {
	// Read stores the start of the next packet in buf. It returns how many
	// bytes were stored and the real length of the packet on the wire.
	// (0, 0, nil) means "nothing arrived in the last second".
	Read(buf []byte) (stored, wireLen int, err error)
	Close() error
}
