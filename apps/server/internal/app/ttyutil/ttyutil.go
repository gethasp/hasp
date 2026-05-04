// Package ttyutil holds the small TTY-shaped helpers that the secret subsystem
// (and a handful of other callers in package app) need: reader-to-*os.File
// extraction, char-device detection, and the stty echo toggle. Keeping these
// in their own package lets the bigger secret surfaces move out of the
// internal/app monolith in later stages without dragging unrelated callers
// (app_path, runtime_commands, app_consumers) along. hasp-xp02
// (Stage 2a of hasp-mgz5).
package ttyutil

import (
	"io"
	"os"
	"os/exec"
)

// ExecCommandFn is the seam used by SetTTYEcho when invoking stty. Tests
// override it to drive the success / failure branches without touching real
// terminal state.
var ExecCommandFn = exec.Command

// StdinFile reports whether reader is the concrete *os.File so callers can
// query its mode. Returns (nil, false) for any non-file reader (or nil).
func StdinFile(reader io.Reader) (*os.File, bool) {
	if reader == nil {
		return nil, false
	}
	if file, ok := reader.(*os.File); ok {
		return file, true
	}
	return nil, false
}

// IsCharDevice reports whether file is a character device (typical for a TTY).
// Returns false for nil files and for files whose Stat call fails.
func IsCharDevice(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// SetTTYEcho toggles terminal echo on file by shelling out to stty. The
// command is invoked through ExecCommandFn so tests can simulate failure
// without owning a real TTY.
func SetTTYEcho(file *os.File, enabled bool) error {
	arg := "-echo"
	if enabled {
		arg = "echo"
	}
	cmd := ExecCommandFn("stty", arg)
	cmd.Stdin = file
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}
