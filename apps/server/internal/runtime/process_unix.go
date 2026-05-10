//go:build unix

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	execCommand      = exec.Command
	processReadFile  = os.ReadFile
	findProcessByPID = os.FindProcess
	releaseProcess   = func(proc *os.Process) error { return proc.Release() }
	signalProcess    = func(proc *os.Process, sig os.Signal) error { return proc.Signal(sig) }
	waitProcess      = func(proc *os.Process) error {
		_, err := proc.Wait()
		return err
	}
)

var (
	daemonStopTimeout      = 5 * time.Second
	daemonStopKillTimeout  = 5 * time.Second
	daemonStopPollInterval = 50 * time.Millisecond
)

func startDetachedProcess(_ context.Context) error {
	if runningTestBinaryWithoutHelper() {
		return errors.New("refusing to start test daemon without HASP_TEST_HELPER_DAEMON=1")
	}
	resolved, err := resolveRuntimePaths()
	if err != nil {
		return err
	}
	if err := runtimeMkdirAll(resolved.RuntimeDir, 0o700); err != nil {
		return fmt.Errorf("create runtime dir: %w", err)
	}
	cmd := execCommand(os.Args[0], "daemon", "serve")
	cmd.Env = os.Environ()
	if os.Getenv("HASP_TEST_HELPER_DAEMON") == "1" {
		cmd.Env = append(cmd.Env, "HASP_TEST_HELPER_PARENT_PID="+strconv.Itoa(os.Getpid()))
	}
	var stdoutFile *os.File
	var stderrFile *os.File
	if os.Getenv("HASP_TEST") == "1" {
		stdoutFile, _ = os.OpenFile(filepath.Join(resolved.RuntimeDir, "daemon.stdout.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		stderrFile, _ = os.OpenFile(filepath.Join(resolved.RuntimeDir, "daemon.stderr.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	}
	if stdoutFile != nil {
		defer func() { _ = stdoutFile.Close() }()
	}
	if stderrFile != nil {
		defer func() { _ = stderrFile.Close() }()
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	if stdoutFile != nil {
		cmd.Stdout = stdoutFile
	}
	if stderrFile != nil {
		cmd.Stderr = stderrFile
	}
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

func runningTestBinaryWithoutHelper() bool {
	return strings.HasSuffix(filepath.Base(os.Args[0]), ".test") && os.Getenv("HASP_TEST_HELPER_DAEMON") != "1"
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
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- waitProcess(proc)
	}()
	if err := signalProcess(proc, syscall.SIGTERM); err != nil {
		return fmt.Errorf("signal daemon: %w", err)
	}
	if waitForProcessExit(proc, waitCh, daemonStopTimeout) {
		_ = runtimeRemove(resolved.PidFilePath)
		return nil
	}
	_ = signalProcess(proc, syscall.SIGKILL)
	if waitForProcessExit(proc, waitCh, daemonStopKillTimeout) {
		_ = runtimeRemove(resolved.PidFilePath)
		return nil
	}
	_ = runtimeRemove(resolved.PidFilePath)
	return fmt.Errorf("timed out waiting for daemon pid %d to exit", pid)
}

func waitForProcessExit(proc *os.Process, waitCh <-chan error, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(daemonStopPollInterval)
	defer ticker.Stop()
	for {
		select {
		case err, ok := <-waitCh:
			if ok && err == nil {
				return true
			}
			waitCh = nil
			if !processStillRunning(proc) {
				return true
			}
		case <-ticker.C:
			if waitCh == nil && !processStillRunning(proc) {
				return true
			}
		case <-timer.C:
			return waitCh == nil && !processStillRunning(proc)
		}
	}
}

func processStillRunning(proc *os.Process) bool {
	err := signalProcess(proc, syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
