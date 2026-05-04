package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func nilContext() context.Context { return nil }

func TestManagerNilContextBranches(t *testing.T) {
	lockRuntimeSeams(t)

	t.Run("ensure daemon nil context", func(t *testing.T) {
		origMkdir := runtimeMkdirAll
		defer func() { runtimeMkdirAll = origMkdir }()
		runtimeMkdirAll = func(string, os.FileMode) error { return errors.New("mkdir fail") }
		manager := &Manager{paths: paths.Paths{
			RuntimeDir: t.TempDir(),
			SocketPath: filepath.Join(t.TempDir(), "daemon.sock"),
		}}
		if err := manager.EnsureDaemon(nilContext()); err == nil {
			t.Fatal("expected nil-context ensure daemon failure")
		}
	})

	t.Run("start daemon nil context", func(t *testing.T) {
		origSpawn := spawnDaemonProcess
		defer func() { spawnDaemonProcess = origSpawn }()
		spawnDaemonProcess = func(ctx context.Context) error {
			if ctx == nil {
				t.Fatal("expected background context")
			}
			return errors.New("spawn fail")
		}
		if err := (&Manager{}).StartDaemon(nilContext()); err == nil {
			t.Fatal("expected nil-context start daemon failure")
		}
	})

	t.Run("run daemon nil context", func(t *testing.T) {
		origMkdir := runtimeMkdirAll
		defer func() { runtimeMkdirAll = origMkdir }()
		runtimeMkdirAll = func(string, os.FileMode) error { return errors.New("mkdir fail") }
		manager := &Manager{paths: paths.Paths{
			RuntimeDir:  t.TempDir(),
			SocketPath:  filepath.Join(t.TempDir(), "daemon.sock"),
			PidFilePath: filepath.Join(t.TempDir(), "daemon.pid"),
		}}
		if err := manager.RunDaemon(nilContext()); err == nil {
			t.Fatal("expected nil-context run daemon failure")
		}
	})
}
