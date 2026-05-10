package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/httpapi"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestRunDaemonStartsHTTPAPIAndCleansPortFile(t *testing.T) {
	home := t.TempDir()
	runtimeDir := filepath.Join(home, "runtime")
	runtimePaths := paths.Paths{
		HomeDir:          home,
		RuntimeDir:       runtimeDir,
		SocketPath:       filepath.Join(runtimeDir, "daemon.sock"),
		PidFilePath:      filepath.Join(runtimeDir, "daemon.pid"),
		HTTPPortFilePath: filepath.Join(home, httpapi.PortFileName),
	}
	manager := &Manager{paths: runtimePaths}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- manager.RunDaemon(ctx) }()
	stopped := false
	defer func() {
		if !stopped {
			cancel()
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("daemon shutdown: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for daemon shutdown")
			}
		}
	}()

	var payload httpapi.PortFileState
	waitForHTTPPortFile(t, runtimePaths.HTTPPortFilePath, &payload)
	if payload.V4 <= 0 || payload.V6 <= 0 {
		t.Fatalf("expected both http ports, got %+v", payload)
	}
	assertConnects(t, "tcp4", net.JoinHostPort("127.0.0.1", itoa(payload.V4)))
	assertConnects(t, "tcp6", net.JoinHostPort("::1", itoa(payload.V6)))

	cancel()
	select {
	case err := <-errCh:
		stopped = true
		if err != nil {
			t.Fatalf("daemon shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for daemon shutdown")
	}
	if _, err := os.Stat(runtimePaths.HTTPPortFilePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected http port file cleanup, got stat err %v", err)
	}
}

func TestRunDaemonFailsWhenHTTPPortFileExists(t *testing.T) {
	home := t.TempDir()
	runtimeDir := filepath.Join(home, "runtime")
	portFile := filepath.Join(home, httpapi.PortFileName)
	if err := os.WriteFile(portFile, []byte(`{"v4":1}`), 0o600); err != nil {
		t.Fatalf("seed port file: %v", err)
	}
	manager := &Manager{paths: paths.Paths{
		HomeDir:          home,
		RuntimeDir:       runtimeDir,
		SocketPath:       filepath.Join(runtimeDir, "daemon.sock"),
		PidFilePath:      filepath.Join(runtimeDir, "daemon.pid"),
		HTTPPortFilePath: portFile,
	}}
	if err := manager.RunDaemon(context.Background()); err == nil || !strings.Contains(err.Error(), "write port file") {
		t.Fatalf("expected port-file startup failure, got %v", err)
	}
}

func waitForHTTPPortFile(t *testing.T, path string, payload *httpapi.PortFileState) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(path)
		if err == nil {
			if err := json.Unmarshal(body, payload); err != nil {
				t.Fatalf("decode http port file: %v", err)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for http port file %s", path)
}

func assertConnects(t *testing.T, network, address string) {
	t.Helper()
	conn, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		t.Fatalf("dial %s %s: %v", network, address, err)
	}
	_ = conn.Close()
}

func itoa(port int) string {
	return strconv.Itoa(port)
}
