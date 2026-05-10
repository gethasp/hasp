package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestNewServerRejectsNonLoopbackBindAddress(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())

	_, err := NewServer(paths.Paths{HomeDir: t.TempDir()}, Options{
		Handler: http.NotFoundHandler(),
		V4Addr:  "0.0.0.0:0",
		V6Addr:  "",
	})
	if err == nil {
		t.Fatal("expected non-loopback bind rejection")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("expected non-loopback error, got %v", err)
	}
}

func TestNewServerRejectsLocalhostAlias(t *testing.T) {
	_, err := NewServer(paths.Paths{HomeDir: t.TempDir()}, Options{
		Handler: http.NotFoundHandler(),
		V4Addr:  "localhost:0",
		V6Addr:  "",
	})
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("expected localhost alias rejection, got %v", err)
	}
}

func TestServerServeWritesExclusivePortFileAndServesLoopback(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)

	server, err := NewServer(paths.Paths{HomeDir: homeDir}, Options{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ctx)
	}()

	state := waitForPortFileState(t, server.PortFilePath())
	if state.V4 == 0 {
		t.Fatal("expected IPv4 port to be recorded")
	}

	info, err := os.Stat(server.PortFilePath())
	if err != nil {
		t.Fatalf("stat port file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("port file mode = %v, want 0600", got)
	}

	assertHTTPGet(t, "http://127.0.0.1:"+itoa(state.V4)+"/health")
	if state.V6 != 0 {
		assertHTTPGet(t, "http://[::1]:"+itoa(state.V6)+"/health")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server shutdown")
	}

	if _, err := os.Stat(server.PortFilePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected port file removal, got %v", err)
	}
}

func TestServerServeRefusesExistingPortFile(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)

	portFilePath := filepath.Join(homeDir, PortFileName)
	if err := os.WriteFile(portFilePath, []byte(`{"v4":1}`), 0o600); err != nil {
		t.Fatalf("seed port file: %v", err)
	}

	server, err := NewServer(paths.Paths{HomeDir: homeDir}, Options{
		Handler: http.NotFoundHandler(),
	})
	if err == nil {
		t.Fatal("expected exclusive port-file write failure")
	}
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected os.ErrExist, got %v", err)
	}
	if server != nil {
		t.Fatal("server should not be returned when port-file write fails")
	}
}

func TestServerServeRefusesSymlinkPortFile(t *testing.T) {
	homeDir := t.TempDir()
	portFilePath := filepath.Join(homeDir, PortFileName)
	targetPath := filepath.Join(homeDir, "target")
	if err := os.WriteFile(targetPath, []byte("target"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Symlink(targetPath, portFilePath); err != nil {
		t.Fatalf("seed symlink: %v", err)
	}

	server, err := NewServer(paths.Paths{HomeDir: homeDir}, Options{
		Handler: http.NotFoundHandler(),
	})
	if err == nil {
		t.Fatal("expected symlink port-file write failure")
	}
	if server != nil {
		t.Fatal("server should not be returned when symlink port-file write fails")
	}
	body, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatalf("read target: %v", readErr)
	}
	if string(body) != "target" {
		t.Fatalf("symlink target was modified: %q", body)
	}
}

func waitForPortFileState(t *testing.T, path string) PortFileState {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			var state PortFileState
			if err := json.Unmarshal(data, &state); err == nil {
				return state
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for port file %s", path)
	return PortFileState{}
}

func assertHTTPGet(t *testing.T, rawURL string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(rawURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out probing %s", rawURL)
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
