//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestMainSetupCtrlCInterruptsInteractivePrompt(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainSetupCtrlCHelper$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		"HASP_MAIN_SETUP_CTRL_C_HELPER=1",
		"HOME="+home,
		"HASP_HOME="+filepath.Join(home, ".hasp"),
		"HASP_TEST=1",
	)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("pty unavailable: %v", err)
	}
	defer ptmx.Close()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	chunks := make(chan string, 16)
	readDone := make(chan error, 1)
	go readMainSetupCtrlCPTY(ptmx, chunks, readDone)

	output := waitForMainSetupPrompt(t, chunks, readDone, 3*time.Second)
	if _, err := ptmx.Write([]byte{0x03}); err != nil {
		t.Fatalf("send ctrl-c after output %q: %v", output, err)
	}

	select {
	case err := <-done:
		if !mainSetupCtrlCExitWasInterrupt(err) {
			t.Fatalf("expected child to stop from terminal interrupt after output %q, got %v", output, err)
		}
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("child did not stop after ctrl-c; output before interrupt: %q", output)
	}
}

func TestMainSetupCtrlCHelper(t *testing.T) {
	if os.Getenv("HASP_MAIN_SETUP_CTRL_C_HELPER") != "1" {
		return
	}
	os.Args = []string{"hasp", "setup"}
	main()
	t.Fatal("main returned unexpectedly")
}

func readMainSetupCtrlCPTY(ptmx *os.File, chunks chan<- string, done chan<- error) {
	buf := make([]byte, 256)
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			chunks <- string(buf[:n])
		}
		if err != nil {
			done <- err
			return
		}
	}
}

func waitForMainSetupPrompt(t *testing.T, chunks <-chan string, readDone <-chan error, timeout time.Duration) string {
	t.Helper()
	deadline := time.After(timeout)
	var seen strings.Builder
	for {
		select {
		case chunk := <-chunks:
			seen.WriteString(chunk)
			if strings.Contains(seen.String(), "Local HASP data directory") {
				return seen.String()
			}
		case err := <-readDone:
			t.Fatalf("child exited before setup prompt; output=%q err=%v", seen.String(), err)
		case <-deadline:
			t.Fatalf("timed out waiting for setup prompt; output=%q", seen.String())
		}
	}
}

func mainSetupCtrlCExitWasInterrupt(err error) bool {
	if err == nil {
		return false
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		return false
	}
	if status.Signaled() {
		return status.Signal() == syscall.SIGINT
	}
	return status.ExitStatus() == 130
}
