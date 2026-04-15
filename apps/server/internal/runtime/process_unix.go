//go:build unix

package runtime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

var (
	execCommand      = exec.Command
	processReadFile  = os.ReadFile
	findProcessByPID = os.FindProcess
	releaseProcess   = func(proc *os.Process) error { return proc.Release() }
	signalProcess    = func(proc *os.Process, sig os.Signal) error { return proc.Signal(sig) }
)

func startDetachedProcess(_ context.Context) error {
	resolved, err := resolveRuntimePaths()
	if err != nil {
		return err
	}
	if err := runtimeMkdirAll(resolved.RuntimeDir, 0o700); err != nil {
		return fmt.Errorf("create runtime dir: %w", err)
	}
	cmd := execCommand(os.Args[0], "daemon", "serve")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}
	if err := writeFile(resolved.PidFilePath, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}
	return releaseProcess(cmd.Process)
}

func stopDetachedProcess() error {
	resolved, err := resolveRuntimePaths()
	if err != nil {
		return err
	}
	data, err := processReadFile(resolved.PidFilePath)
	if err != nil {
		return fmt.Errorf("read pid file: %w", err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return fmt.Errorf("parse pid: %w", err)
	}
	proc, err := findProcessByPID(pid)
	if err != nil {
		return fmt.Errorf("find process: %w", err)
	}
	if err := signalProcess(proc, syscall.SIGTERM); err != nil {
		return fmt.Errorf("signal daemon: %w", err)
	}
	_ = runtimeRemove(resolved.PidFilePath)
	return nil
}
