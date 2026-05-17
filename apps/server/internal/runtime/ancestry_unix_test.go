//go:build unix

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestProcessLineageAndParentPID(t *testing.T) {
	parent, err := processParentPID(os.Getpid())
	if err != nil {
		t.Fatalf("processParentPID: %v", err)
	}
	if parent <= 0 {
		t.Fatalf("expected positive parent pid, got %d", parent)
	}
	lineage, err := processLineage(os.Getpid())
	if err != nil {
		t.Fatalf("processLineage: %v", err)
	}
	if len(lineage) == 0 || lineage[0] != os.Getpid() {
		t.Fatalf("unexpected lineage %+v", lineage)
	}
	if lineage, err := processLineage(0); err != nil || lineage != nil {
		t.Fatalf("expected zero pid to short-circuit, got %+v err=%v", lineage, err)
	}
}

func TestProcessLineageAdditionalBranches(t *testing.T) {
	lockRuntimeSeams(t)

	origParentPID := processParentPID
	defer func() { processParentPID = origParentPID }()

	processParentPID = func(pid int) (int, error) {
		switch pid {
		case 44:
			return 43, nil
		case 43:
			return 1, nil
		default:
			return 0, nil
		}
	}
	lineage, err := processLineage(44)
	if err != nil || len(lineage) != 2 || lineage[0] != 44 || lineage[1] != 43 {
		t.Fatalf("expected synthetic lineage, got %+v err=%v", lineage, err)
	}

	processParentPID = func(pid int) (int, error) {
		if pid == 50 {
			return 0, errors.New("lookup failed")
		}
		return 0, nil
	}
	lineage, err = processLineage(50)
	if err != nil || len(lineage) != 1 || lineage[0] != 50 {
		t.Fatalf("expected partial lineage on parent failure, got %+v err=%v", lineage, err)
	}

	processParentPID = func(pid int) (int, error) {
		if pid == 60 {
			return 60, nil
		}
		return 0, nil
	}
	lineage, err = processLineage(60)
	if err != nil || len(lineage) != 1 || lineage[0] != 60 {
		t.Fatalf("expected self-parent break, got %+v err=%v", lineage, err)
	}
	if parent, err := processParentPID(61); err != nil || parent != 0 {
		t.Fatalf("expected blank parent pid to map to zero, got %d err=%v", parent, err)
	}

	processParentPID = func(pid int) (int, error) {
		switch pid {
		case 70:
			return 69, nil
		case 69:
			return 70, nil
		default:
			return 0, nil
		}
	}
	lineage, err = processLineage(70)
	if err != nil || len(lineage) != 2 || lineage[0] != 70 || lineage[1] != 69 {
		t.Fatalf("expected cycle break lineage, got %+v err=%v", lineage, err)
	}
}

func TestRealVerifyDaemonPIDRejectsInvalidInputs(t *testing.T) {
	if realVerifyDaemonPID("", 1) {
		t.Fatal("empty socket path should not verify")
	}
	if realVerifyDaemonPID("/tmp/missing-hasp.sock", 0) {
		t.Fatal("zero pid should not verify")
	}
	if realVerifyDaemonPID("/tmp/missing-hasp.sock", 12345) {
		t.Fatal("missing socket should not verify")
	}
}

func TestRealVerifyDaemonPIDRejectsPeerPIDMismatch(t *testing.T) {
	lockRuntimeSeams(t)
	home := t.TempDir()
	socket := filepath.Join("/tmp", "hasp-verify-mismatch-"+time.Now().UTC().Format("150405.000000000")+".sock")
	t.Setenv(paths.EnvHome, home)
	t.Setenv(paths.EnvSocket, socket)
	t.Cleanup(func() { _ = os.Remove(socket) })

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- manager.RunDaemon(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("daemon exited: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for daemon shutdown")
		}
	})
	if err := waitForSocket(manager.SocketPath(), 2*time.Second); err != nil {
		t.Fatalf("wait for socket: %v", err)
	}
	if realVerifyDaemonPID(manager.SocketPath(), os.Getpid()+1) {
		t.Fatal("peer PID mismatch should not verify daemon pid")
	}
}
