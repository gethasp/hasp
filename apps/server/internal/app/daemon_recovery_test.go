package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestDoctorFixRestartsAfterDaemonCrash(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	socketPath := shortSocketPath(t, fmt.Sprintf("hasp-recover-%d.sock", time.Now().UnixNano()))
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_SOCKET", socketPath)
	t.Setenv("HASP_TEST_HELPER_DAEMON", "1")

	starter, err := newRuntimeStarter()
	if err != nil {
		t.Fatalf("new runtime starter: %v", err)
	}
	manager, err := runtime.NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() {
		_ = manager.StopDaemon()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := starter.EnsureDaemon(ctx); err != nil {
		t.Fatalf("ensure daemon: %v", err)
	}
	if err := waitForSocketReady(manager.SocketPath(), make(chan error), 5*time.Second); err != nil {
		t.Fatalf("daemon ready: %v", err)
	}

	pid, err := readDaemonPID(filepath.Join(homeDir, "runtime", "daemon.pid"))
	if err != nil {
		t.Fatalf("read daemon pid: %v", err)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill daemon: %v", err)
	}
	waitForNotRunningStatus(t, starter)

	var before bytes.Buffer
	if err := statusCommand(context.Background(), &before, starter); err != nil {
		t.Fatalf("status after crash: %v", err)
	}
	if !strings.Contains(before.String(), "not running") {
		t.Fatalf("expected not running status after crash, got %q", before.String())
	}

	var doctorOut bytes.Buffer
	if err := runWithStarter(
		context.Background(),
		[]string{"doctor", "--fix", "--json"},
		bytes.NewBuffer(nil),
		&doctorOut,
		&doctorOut,
		starter,
	); err != nil {
		t.Fatalf("doctor --fix --json: %v\n%s", err, doctorOut.String())
	}

	var report struct {
		DaemonRunning bool `json:"daemon_running"`
	}
	if err := json.Unmarshal(doctorOut.Bytes(), &report); err != nil {
		t.Fatalf("decode doctor report: %v\n%s", err, doctorOut.String())
	}
	if !report.DaemonRunning {
		t.Fatalf("doctor report did not recover daemon: %s", doctorOut.String())
	}

	var after bytes.Buffer
	if err := statusCommand(context.Background(), &after, starter); err != nil {
		t.Fatalf("status after recovery: %v", err)
	}
	if strings.Contains(after.String(), "not running") {
		t.Fatalf("expected recovered daemon status, got %q", after.String())
	}
}

func readDaemonPID(path string) (int, error) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
			if parseErr == nil && pid > 0 {
				return pid, nil
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return 0, fmt.Errorf("timed out waiting for daemon pid at %s", path)
}

func waitForNotRunningStatus(t *testing.T, s starter) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var out bytes.Buffer
		if err := statusCommand(context.Background(), &out, s); err == nil && strings.Contains(out.String(), "not running") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for daemon to report not running")
}
