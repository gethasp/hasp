package app

// RED tests for hasp-vl40 — `hasp doctor --fix`. Contract pinned:
//
//   - --fix attempts to repair a documented set of common breakage:
//     stale socket files, HASP_HOME perms tighter than 0700, and missing
//     daemon (started via the existing starter seam).
//   - Fix attempts are reported as a "fixes_attempted" / "fixes_succeeded"
//     pair in the human and JSON output so the operator can see what was
//     touched.
//   - Without --fix, doctor's behaviour is unchanged. Adding the flag is
//     purely additive.

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorFixTightensHaspHomePerms(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := os.Chmod(homeDir, 0o755); err != nil {
		t.Fatalf("chmod loose: %v", err)
	}
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Re-loosen post-init in case init tightened them.
	if err := os.Chmod(homeDir, 0o755); err != nil {
		t.Fatalf("chmod loose: %v", err)
	}
	starter := newDaemonTestStarter(t)
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"doctor", "--fix"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("doctor --fix: %v", err)
	}
	_ = starter
	info, err := os.Stat(homeDir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Fatalf("expected HASP_HOME perms 0700 after --fix, got %#o", mode)
	}
	if !strings.Contains(stdout.String(), "fixes_attempted") {
		t.Fatalf("expected fixes_attempted line in output, got %q", stdout.String())
	}
}

func TestDoctorFixRemovesStaleSocketFile(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Create a stale socket file under HASP_HOME — a regular file with the
	// .sock suffix that no live daemon owns.
	stale := filepath.Join(homeDir, "stale.sock")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale: %v", err)
	}
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"doctor", "--fix"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("doctor --fix: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("expected stale socket %s to be removed; got err=%v", stale, err)
	}
}

func TestDoctorWithoutFixDoesNotMutateState(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := os.Chmod(homeDir, 0o755); err != nil {
		t.Fatalf("chmod loose: %v", err)
	}
	stale := filepath.Join(homeDir, "stale.sock")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale: %v", err)
	}
	if err := Run(context.Background(), []string{"doctor"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("doctor: %v", err)
	}
	info, err := os.Stat(homeDir)
	if err != nil {
		t.Fatalf("stat home: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o755 {
		t.Fatalf("doctor without --fix should not change perms; got %#o", mode)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("doctor without --fix should not remove stale socket; got err=%v", err)
	}
}
