//go:build !windows

package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestSetupPasswordPromptTerminalCtrlCStopsBeforeVaultWrite(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSetupPasswordPromptTerminalCtrlCHelper$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		"HASP_SETUP_CTRL_C_HELPER=1",
		"HASP_SETUP_CTRL_C_HOME="+home,
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
	go readSetupCtrlCPTY(ptmx, chunks, readDone)

	output := waitForSetupCtrlCPrompt(t, chunks, readDone, 3*time.Second)
	if _, err := ptmx.Write([]byte{0x03}); err != nil {
		t.Fatalf("send ctrl-c after output %q: %v", output, err)
	}

	select {
	case err := <-done:
		if !setupCtrlCExitWasInterrupt(err) {
			t.Fatalf("expected child to stop from terminal interrupt after output %q, got %v", output, err)
		}
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("child did not stop after ctrl-c; output before interrupt: %q", output)
	}

	if _, err := os.Stat(filepath.Join(home, "vault.json.enc")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("vault file should not exist after interrupted password prompt: %v", err)
	}
}

func TestSetupPasswordPromptTerminalCtrlCHelper(t *testing.T) {
	if os.Getenv("HASP_SETUP_CTRL_C_HELPER") != "1" {
		return
	}
	lockAppSeams(t)
	home := os.Getenv("HASP_SETUP_CTRL_C_HOME")
	if home == "" {
		t.Fatal("HASP_SETUP_CTRL_C_HOME is required")
	}
	if _, _, err := setupResolvePassword(newSetupPrompter(os.Stdin, os.Stdout), setupOptions{}, home); err != nil {
		fmt.Fprintf(os.Stderr, "setupResolvePassword returned before interrupt: %v\n", err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "setupResolvePassword completed unexpectedly")
	os.Exit(3)
}

func readSetupCtrlCPTY(ptmx *os.File, chunks chan<- string, done chan<- error) {
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

func waitForSetupCtrlCPrompt(t *testing.T, chunks <-chan string, readDone <-chan error, timeout time.Duration) string {
	t.Helper()
	deadline := time.After(timeout)
	var seen strings.Builder
	for {
		select {
		case chunk := <-chunks:
			seen.WriteString(chunk)
			if strings.Contains(seen.String(), "Choose a local HASP master password") {
				return seen.String()
			}
		case err := <-readDone:
			t.Fatalf("child exited before password prompt; output=%q err=%v", seen.String(), err)
		case <-deadline:
			t.Fatalf("timed out waiting for password prompt; output=%q", seen.String())
		}
	}
}

func setupCtrlCExitWasInterrupt(err error) bool {
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
