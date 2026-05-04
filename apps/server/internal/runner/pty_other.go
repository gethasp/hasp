//go:build !darwin && !linux

package runner

import (
	"context"
	"errors"
	"os/exec"
)

// ErrTTYUnsupported is returned by executePTY on platforms without a PTY
// implementation. Callers handle this by falling back to the non-TTY path.
var ErrTTYUnsupported = errors.New("PTY allocation is only supported on darwin and linux")

func executePTY(_ context.Context, _ *exec.Cmd, _ Input) ([]byte, int, error) {
	return nil, 0, ErrTTYUnsupported
}
