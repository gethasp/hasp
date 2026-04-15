//go:build unix

package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestStartAndStopDetachedProcess(t *testing.T) {
	home := t.TempDir()
	socket := filepath.Join("/tmp", "hasp-process-test.sock")
	t.Setenv(paths.EnvHome, home)
	t.Setenv(paths.EnvSocket, socket)
	t.Setenv("HASP_TEST_HELPER_DAEMON", "1")
	t.Cleanup(func() {
		_ = os.Remove(socket)
	})

	if err := startDetachedProcess(context.Background()); err != nil {
		t.Fatalf("start detached process: %v", err)
	}
	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := waitForSocket(manager.SocketPath(), 2*time.Second); err != nil {
		t.Fatalf("wait for socket: %v", err)
	}
	if err := stopDetachedProcess(); err != nil {
		t.Fatalf("stop detached process: %v", err)
	}
}
