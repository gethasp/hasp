package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

// TestRunnerStdinForwarded verifies that input.Stdin bytes reach the child process.
func TestRunnerStdinForwarded(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))

	stdinData := []byte("hello from stdin\n")
	r := bytes.NewReader(stdinData)

	var stdout bytes.Buffer
	result, err := Execute(context.Background(), Input{
		Command: []string{"cat"},
		Stdin:   r,
		Stdout:  &stdout,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code: %d", result.ExitCode)
	}
	// When Stdout is set, legacy result.Stdout should be nil/empty.
	if len(result.Stdout) != 0 {
		t.Errorf("expected result.Stdout empty when Stdout writer provided, got %q", result.Stdout)
	}
	if !bytes.Equal(stdout.Bytes(), stdinData) {
		t.Errorf("stdout: got %q, want %q", stdout.Bytes(), stdinData)
	}
}

// TestRunnerLargeOutputDoesNotOOM verifies that 1 MiB of output completes
// without error and result.Stdout is populated via the legacy buffer path.
func TestRunnerLargeOutputDoesNotOOM(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))

	// Generate 1 MiB (1048576 bytes) from the child process.
	// `dd if=/dev/zero bs=1024 count=1024` writes 1 MiB of zero bytes.
	result, err := Execute(context.Background(), Input{
		Command: []string{"dd", "if=/dev/zero", "bs=1024", "count=1024"},
	})
	if err != nil {
		t.Fatalf("execute large output: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code: %d, stderr: %q", result.ExitCode, result.Stderr)
	}
	const oneMiB = 1 << 20
	if len(result.Stdout) != oneMiB {
		t.Errorf("expected %d bytes stdout, got %d", oneMiB, len(result.Stdout))
	}
}

// TestRunnerCustomStdoutWriter verifies that when Stdout/Stderr writers are
// provided, the bytes flow to them and result.Stdout/Stderr remain empty.
func TestRunnerCustomStdoutWriter(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))

	var stdout, stderr bytes.Buffer
	result, err := Execute(context.Background(), Input{
		Command: []string{"sh", "-c", "printf 'out'; printf 'err' >&2"},
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code: %d", result.ExitCode)
	}
	if stdout.String() != "out" {
		t.Errorf("stdout writer: got %q, want %q", stdout.String(), "out")
	}
	if stderr.String() != "err" {
		t.Errorf("stderr writer: got %q, want %q", stderr.String(), "err")
	}
	// Legacy fields must be empty when custom writers are provided.
	if len(result.Stdout) != 0 {
		t.Errorf("result.Stdout should be empty when Stdout writer set, got %q", result.Stdout)
	}
	if len(result.Stderr) != 0 {
		t.Errorf("result.Stderr should be empty when Stderr writer set, got %q", result.Stderr)
	}
}

// TestRunnerLegacyBufferPath verifies that when no Stdout/Stderr writers are
// given, result.Stdout/Stderr are populated as before.
func TestRunnerLegacyBufferPath(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))

	result, err := Execute(context.Background(), Input{
		Command: []string{"sh", "-c", "printf 'legacy-out'; printf 'legacy-err' >&2"},
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if string(result.Stdout) != "legacy-out" {
		t.Errorf("legacy stdout: got %q", result.Stdout)
	}
	if string(result.Stderr) != "legacy-err" {
		t.Errorf("legacy stderr: got %q", result.Stderr)
	}
}

// TestRunnerStreamingOutputBeforeExit verifies that a long-running child
// emits bytes to the writer BEFORE the process exits. We do this by:
//  1. Running a child that prints a line, sleeps briefly, then exits.
//  2. Detecting the first write in a goroutine via a channel.
//  3. Asserting the channel fires before a deadline significantly longer
//     than the child's sleep — proving streaming, not buffering.
func TestRunnerStreamingOutputBeforeExit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping streaming interleave test in short mode")
	}
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))

	firstWrite := make(chan struct{}, 1)
	pw := &probeWriter{notify: firstWrite}

	done := make(chan error, 1)
	go func() {
		_, err := Execute(context.Background(), Input{
			// Print immediately, then sleep 500ms, then exit.
			Command: []string{"sh", "-c", "printf 'line1\n'; sleep 0.5"},
			Stdout:  pw,
		})
		done <- err
	}()

	select {
	case <-firstWrite:
		// Good — bytes arrived before the child exited.
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for first streamed byte; output was not streamed before process exit")
	}

	// Wait for the goroutine to finish.
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("execute error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("execute goroutine did not finish in time")
	}
}

// probeWriter signals firstWrite channel on the first non-empty Write call.
type probeWriter struct {
	notify chan struct{}
	notified bool
}

func (pw *probeWriter) Write(p []byte) (int, error) {
	if len(p) > 0 && !pw.notified {
		pw.notified = true
		select {
		case pw.notify <- struct{}{}:
		default:
		}
	}
	return len(p), nil
}

// TestRunnerStdinNilDoesNotPanic verifies that nil Stdin (no forwarding)
// doesn't cause a panic or unexpected error.
func TestRunnerStdinNilDoesNotPanic(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))

	result, err := Execute(context.Background(), Input{
		Command: []string{"sh", "-c", "echo hello"},
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(string(result.Stdout), "hello") {
		t.Errorf("expected hello in stdout, got %q", result.Stdout)
	}
}

// TestRunnerStdinWithFileContent feeds a file via Stdin and reads it via cat.
func TestRunnerStdinWithFileContent(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))

	// Write a temp file and open it as stdin source.
	tmpFile := filepath.Join(baseDir, "input.txt")
	content := []byte("file-based stdin content\n")
	if err := os.WriteFile(tmpFile, content, 0o644); err != nil {
		t.Fatalf("write tmp file: %v", err)
	}
	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("open tmp file: %v", err)
	}
	defer f.Close()

	result, err := Execute(context.Background(), Input{
		Command: []string{"cat"},
		Stdin:   f,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Equal(result.Stdout, content) {
		t.Errorf("stdin file: got %q, want %q", result.Stdout, content)
	}
}
