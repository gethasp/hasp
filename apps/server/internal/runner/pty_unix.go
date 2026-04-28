//go:build darwin || linux

package runner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"

	"github.com/creack/pty"
)

// executePTY runs cmd attached to a freshly allocated pty pair, copies
// pty.master ↔ input.Stdin/Stdout, and returns when the child exits and the
// master→stdout copy has drained.
//
// PTYs merge stdout and stderr so input.Stderr is ignored; everything the
// child writes to either fd flows through input.Stdout. Callers wrapping
// Stdout in redactor.NewStreamingWriterANSIAware get correct redaction even
// when the child emits ANSI escapes (which it now will, having detected an
// interactive terminal).
//
// Returns the buffered fallback bytes (only when input.Stdout is nil) and
// the child's exit code. Errors other than ExitError propagate verbatim.
//
// Build tag: darwin || linux. Other platforms fall through to a stub that
// returns ErrTTYUnsupported so callers can fall back to the non-TTY path.
func executePTY(ctx context.Context, cmd *exec.Cmd, input Input) ([]byte, int, error) {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, 0, err
	}
	defer ptmx.Close()

	var fallback bytes.Buffer
	dst := input.Stdout
	if dst == nil {
		dst = &fallback
	}

	var copyDone sync.WaitGroup
	copyDone.Add(1)
	go func() {
		defer copyDone.Done()
		_, _ = io.Copy(dst, ptmx)
	}()

	if input.Stdin != nil {
		go func() {
			_, _ = io.Copy(ptmx, input.Stdin)
		}()
	}

	waitErr := cmd.Wait()
	// Closing the master here makes any in-progress io.Copy from input.Stdin
	// return so the goroutine exits — and forces the master→dst Copy to
	// return EOF promptly so we don't deadlock waiting on copyDone.
	_ = ptmx.Close()
	copyDone.Wait()

	if waitErr == nil {
		return fallback.Bytes(), 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return fallback.Bytes(), exitErr.ExitCode(), nil
	}
	return fallback.Bytes(), 0, waitErr
}
