//go:build !darwin && !linux

package runner

import (
	"os/exec"
	"time"
)

func configureProcessGroup(cmd *exec.Cmd) { cmd.WaitDelay = 2 * time.Second }
