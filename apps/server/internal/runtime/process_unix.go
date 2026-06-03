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
	verifyDaemonPID  = realVerifyDaemonPID
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

// filterDaemonEnv drops credentials from the environment handed to the long-lived
// daemon so they don't linger in /proc/<daemon>/environ, readable by same-UID
// processes (hasp-f373): the per-run session bearer token (which the daemon never
// consumes) and the vault-unlocking secrets (master password / backup passphrase),
// which are instead passed over a one-shot pipe and read once at startup.
func filterDaemonEnv(parent []string) []string {
	out := parent[:0:0]
outer:
	for _, kv := range parent {
		if strings.HasPrefix(kv, "HASP_SESSION_TOKEN=") {
			continue
		}
		for _, name := range sensitiveDaemonEnvNames {
			if strings.HasPrefix(kv, name+"=") {
				continue outer
			}
		}
		out = append(out, kv)
	}
	return out
}

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
	parentEnviron := os.Environ()
	// Strip credentials from the daemon's inherited env (session token + the
	// vault-unlocking secrets) so they don't sit in /proc/<daemon>/environ
	// (hasp-f373). The unlocking secrets, if present, are passed over a one-shot
	// pipe (fd) below and read once at daemon startup, never via the environment.
	cmd.Env = filterDaemonEnv(parentEnviron)
	if os.Getenv("HASP_TEST_HELPER_DAEMON") == "1" {
		cmd.Env = append(cmd.Env, "HASP_TEST_HELPER_PARENT_PID="+strconv.Itoa(os.Getpid()))
	}
	var secretReadEnd, secretWriteEnd *os.File
	var secretBlob []byte
	if hasSensitiveEnv(parentEnviron) {
		pr, pw, perr := os.Pipe()
		if perr != nil {
			return fmt.Errorf("create secret env pipe: %w", perr)
		}
		secretReadEnd, secretWriteEnd = pr, pw
		secretBlob = encodeSecretEnvBlob(parentEnviron)
		cmd.ExtraFiles = append(cmd.ExtraFiles, pr) // first ExtraFile => fd 3 in child
		cmd.Env = append(cmd.Env, secretEnvFDVar+"=3")
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
		if secretReadEnd != nil {
			_ = secretReadEnd.Close()
		}
		if secretWriteEnd != nil {
			_ = secretWriteEnd.Close()
		}
		return fmt.Errorf("start daemon: %w", err)
	}
	if secretWriteEnd != nil {
		// The child holds the read end now; the parent writes the secrets and
		// closes both ends so the child sees EOF after the (tiny) blob.
		_ = secretReadEnd.Close()
		_, _ = secretWriteEnd.Write(secretBlob)
		_ = secretWriteEnd.Close()
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
	if resolved.SocketPath != "" && !verifyDaemonPID(resolved.SocketPath, pid) {
		_ = runtimeRemove(resolved.PidFilePath)
		return fmt.Errorf("refusing to signal daemon pid %d: pidfile does not match live HASP daemon socket", pid)
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

func realVerifyDaemonPID(socketPath string, pid int) bool {
	if strings.TrimSpace(socketPath) == "" || pid <= 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	client, err := Dial(ctx, socketPath)
	if err != nil {
		return false
	}
	defer client.Close()
	peerPID, err := realPeerPID(client.conn)
	if err != nil || int(peerPID) != pid {
		return false
	}
	status, err := client.Status(ctx)
	return err == nil && status.PID == pid && status.SocketPath == socketPath
}
