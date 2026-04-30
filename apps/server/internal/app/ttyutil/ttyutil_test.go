package ttyutil

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

func TestStdinFileAndIsCharDevice(t *testing.T) {
	if file, ok := StdinFile(nil); ok || file != nil {
		t.Fatalf("nil reader = %v %v", file, ok)
	}
	if file, ok := StdinFile(bytes.NewBuffer(nil)); ok || file != nil {
		t.Fatalf("buffer reader = %v %v", file, ok)
	}
	tmp, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer tmp.Close()
	if file, ok := StdinFile(tmp); !ok || file != tmp {
		t.Fatalf("file reader = %v %v", file, ok)
	}
	if IsCharDevice(nil) {
		t.Fatal("nil should not be char device")
	}
	if IsCharDevice(tmp) {
		t.Fatal("regular file should not be char device")
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatalf("closed temp file: %v", err)
	}
	closed.Close()
	_ = os.Remove(closed.Name())
	if IsCharDevice(closed) {
		t.Fatal("closed removed file should not be char device")
	}
}

func TestSetTTYEchoUsesConfiguredCommand(t *testing.T) {
	origExec := ExecCommandFn
	t.Cleanup(func() { ExecCommandFn = origExec })
	var calls []string
	ExecCommandFn = func(name string, args ...string) *exec.Cmd {
		calls = append(calls, append([]string{name}, args...)...)
		return exec.Command("sh", "-c", "exit 0")
	}
	if err := SetTTYEcho(nil, false); err != nil {
		t.Fatalf("disable echo: %v", err)
	}
	if err := SetTTYEcho(nil, true); err != nil {
		t.Fatalf("enable echo: %v", err)
	}
	if len(calls) != 4 || calls[0] != "stty" || calls[1] != "-echo" || calls[2] != "stty" || calls[3] != "echo" {
		t.Fatalf("unexpected calls: %#v", calls)
	}

	ExecCommandFn = func(string, ...string) *exec.Cmd {
		return exec.Command("sh", "-c", "exit 7")
	}
	if err := SetTTYEcho(nil, true); err == nil {
		t.Fatal("expected command failure")
	}
}
