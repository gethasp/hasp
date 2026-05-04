//go:build linux

package runtime

import (
	"fmt"
	"os"
	"strings"
)

var processIdentityReadFile = os.ReadFile

// realProcessIdentity reads /proc/<pid>/stat and returns field 22
// (starttime, in clock ticks since boot). Linux PIDs may be reused but the
// (pid, starttime) pair is unique for the lifetime of the kernel, so a
// changed starttime is a reliable PID-reuse signal.
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
		return "", nil // /proc unavailable or process gone — advisory mode
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
