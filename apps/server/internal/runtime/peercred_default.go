//go:build !linux && !darwin

package runtime

import (
	"fmt"
	"net"
)

// realPeerUID is a stub for non-unix platforms (e.g. Windows). It always
// returns an error so the accept loop rejects all connections fail-closed.
func realPeerUID(_ net.Conn) (uint32, error) {
	return 0, fmt.Errorf("peer credential lookup: unsupported platform")
}

// realPeerPID is a stub for non-unix platforms — always returns an error so
// privileged operations fail closed.
func realPeerPID(_ net.Conn) (uint32, error) {
	return 0, fmt.Errorf("peer credential lookup: unsupported platform")
}
