//go:build darwin || linux

package runner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
)

// ptyDrainTimeout bounds how long executePTY waits for the master→dst io.Copy
// to drain after the child exits before force-closing the master. On Linux
// the slave side closes when the child exits and the master read returns
// buffered bytes followed by EIO/EOF, so the copy goroutine drains itself —
// but a detached grandchild that inherited the slave fd can keep it open
// indefinitely. The timeout caps that case while still letting fast-exit
// children deliver their final bytes (race window seen on Linux CI: small
// `printf` writes were lost when ptmx was closed before the goroutine had
// been scheduled to read them).
var ptyDrainTimeout = 100 * time.Millisecond

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
	// On Linux the slave end of the pty closes when the child exits, so the
	// master read returns any buffered bytes followed by EIO/EOF and the
	// master→dst io.Copy goroutine drains naturally. Wait for that drain
	// before force-closing ptmx; otherwise a fast-exit child like
	// `printf hello` can lose its final bytes when ptmx.Close() races with
	// a not-yet-scheduled goroutine read.
	//
	// Bound the wait so a detached grandchild that kept the slave fd open
	// can't stall us forever: after the timeout we close the master, which
	// breaks the copy goroutine's read so it can finish.
	drained := make(chan struct{})
	go func() {
		copyDone.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(ptyDrainTimeout):
	}
	_ = ptmx.Close()
	<-drained

	if waitErr == nil {
		return fallback.Bytes(), 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return fallback.Bytes(), exitErr.ExitCode(), nil
	}
	return fallback.Bytes(), 0, waitErr
}
