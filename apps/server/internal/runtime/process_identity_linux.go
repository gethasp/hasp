//go:build linux

package runtime

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

var processIdentityReadFile = os.ReadFile

// realProcessIdentity reads /proc/<pid>/stat and returns field 22
// (starttime, in clock ticks since boot). Linux PIDs may be reused, so a
// changed starttime is useful only as a stale-binding signal. It is not an
// authorization capability.
//
// The /proc/<pid>/stat format is documented in proc(5). Field 2 (comm) is
// parenthesized and may itself contain whitespace and parens, so we split
// from the right of the closing paren rather than tokenizing from the start.
func realProcessIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", nil
	}
	data, err := processIdentityReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", nil // /proc unavailable or process gone; callers fail closed.
	}
	body := string(data)
	closeParen := strings.LastIndexByte(body, ')')
	if closeParen < 0 || closeParen+2 >= len(body) {
		return "", nil
	}
	rest := strings.Fields(body[closeParen+2:])
	// rest[0] is field 3 (state); field 22 is rest[19].
	if len(rest) < 20 {
		return "", nil
	}
	return rest[19], nil
}

func realProcessParentPID(pid int) (int, error) {
	if pid <= 0 {
		return 0, nil
	}
	data, err := processIdentityReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("resolve parent pid: %w", err)
	}
	body := string(data)
	closeParen := strings.LastIndexByte(body, ')')
	if closeParen < 0 || closeParen+2 >= len(body) {
		return 0, fmt.Errorf("parse parent pid: malformed proc stat")
	}
	rest := strings.Fields(body[closeParen+2:])
	// rest[0] is field 3 (state); field 4 (ppid) is rest[1].
	if len(rest) < 2 {
		return 0, fmt.Errorf("parse parent pid: short proc stat")
	}
	parent, err := strconv.Atoi(rest[1])
	if err != nil {
		return 0, fmt.Errorf("parse parent pid: %w", err)
	}
	return parent, nil
}
