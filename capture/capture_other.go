//go:build !linux

package capture

import "errors"

// Open is not available outside Linux in this version.
func Open(iface string, promisc bool) (Source, error) {
	return nil, errors.New("live packet capture is only available on Linux in this version")
}
