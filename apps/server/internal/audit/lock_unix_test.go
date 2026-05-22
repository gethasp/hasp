//go:build darwin || linux || freebsd || openbsd || netbsd

package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLockAuditFileUnixCoversPlatformFailures(t *testing.T) {
	baseDir := t.TempDir()

	unlock, err := lockAuditFile(filepath.Join(baseDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("lock audit file: %v", err)
	}
	unlock()

	if _, err := os.Stat(filepath.Join(baseDir, "audit.jsonl.lock")); err != nil {
		t.Fatalf("expected lock file to remain for reuse: %v", err)
	}

	blockingFile := filepath.Join(baseDir, "blocking-file")
	if err := os.WriteFile(blockingFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}
	if _, err := lockAuditFile(filepath.Join(blockingFile, "audit.jsonl")); err == nil || !strings.Contains(err.Error(), "open audit lock") {
		t.Fatalf("expected open audit lock failure, got %v", err)
	}

	originalFlock := auditFlock
	auditFlock = func(int, int) error {
		return errors.New("flock failed")
	}
	t.Cleanup(func() {
		auditFlock = originalFlock
	})

	if _, err := lockAuditFile(filepath.Join(baseDir, "flock-failure.jsonl")); err == nil || !strings.Contains(err.Error(), "lock audit log") {
		t.Fatalf("expected lock audit log failure, got %v", err)
	}

	auditFlock = func(_ int, op int) error {
		if op == syscall.LOCK_UN {
			return errors.New("unlock ignored")
		}
		return nil
	}
	unlock, err = lockAuditFile(filepath.Join(baseDir, "unlock-failure.jsonl"))
	if err != nil {
		t.Fatalf("lock audit file with unlock failure hook: %v", err)
	}
	unlock()
}
