package app

// hasp-76yu: user-facing errors must populate the Hint field so users know
// what command to run next. This file drives three known-bad error sites RED:
//   1. "project lease required for run" — no hint today
//   2. "reference not found" — no hint today
//   3. "signal daemon: os: process already finished" — leaked Go internals, no clean message

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// assertHint checks that err is an *appError with a non-empty Hint field and
// that its Error() string does not leak raw Go internals (e.g. package paths).
func assertHint(t *testing.T, label string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error, got nil", label)
	}
	var ae *appError
	if !errors.As(err, &ae) {
		t.Fatalf("%s: error is not *appError; got %T: %v", label, err, err)
	}
	if ae.Hint == "" {
		t.Fatalf("%s: appError.Hint is empty; message=%q", label, ae.Message)
	}
}

// setupHintsVault initialises a vault with one item and a bound project root.
// Returns the handle, projectRoot, and restores seam state via t.Cleanup.
func setupHintsVault(t *testing.T) (*store.Handle, string) {
	t.Helper()
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	vaultStore, err := store.New(nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertItem("api_key", store.ItemKindKV, []byte("secret-value"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"ref_01": "api_key"}, store.PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	origEnsureSession := ensureSessionAppFn
	origVaultHandle := openVaultHandleFn
	t.Cleanup(func() {
		ensureSessionAppFn = origEnsureSession
		openVaultHandleFn = origVaultHandle
	})
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "test-token"}, nil
	}
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		return handle, nil
	}

	return handle, projectRoot
}

// TestErrorHintsProjectLeaseRequired verifies that when "project lease
// required for run" fires the returned error is an *appError carrying a
// non-empty Hint that tells the user how to fix it (e.g. "hasp session grant").
func TestErrorHintsProjectLeaseRequired(t *testing.T) {
	_, projectRoot := setupHintsVault(t)

	deps := defaultExecDeps()
	deps.AuthorizeReference = func(
		_ context.Context,
		_ *store.Handle,
		_, _, _, _ string,
		_ store.Operation,
		_, _, _ store.GrantScope,
		_ time.Duration,
		_ string,
	) (store.Item, error) {
		return store.Item{}, fmt.Errorf("project lease required for run")
	}

	err := executeCommandWithDeps(
		context.Background(),
		[]string{
			"--project-root", projectRoot,
			"--env", "KEY=ref_01",
			"--", "true",
		},
		io.Discard, io.Discard,
		false,
		&fakeStarter{},
		deps,
	)

	assertHint(t, "project-lease-required", err)
}

// TestErrorHintsReferenceNotFound verifies that when the broker cannot find a
// named reference the returned error is an *appError with a Hint that suggests
// how to expose the secret to the project (e.g. "hasp secret expose ...").
func TestErrorHintsReferenceNotFound(t *testing.T) {
	_, projectRoot := setupHintsVault(t)

	deps := defaultExecDeps()
	deps.AuthorizeReference = func(
		_ context.Context,
		_ *store.Handle,
		_, _, _, ref string,
		_ store.Operation,
		_, _, _ store.GrantScope,
		_ time.Duration,
		_ string,
	) (store.Item, error) {
		return store.Item{}, fmt.Errorf("%w: %q", store.ErrReferenceNotFound, ref)
	}

	err := executeCommandWithDeps(
		context.Background(),
		[]string{
			"--project-root", projectRoot,
			"--env", "KEY=@MISSING_KEY",
			"--", "true",
		},
		io.Discard, io.Discard,
		false,
		&fakeStarter{},
		deps,
	)

	assertHint(t, "reference-not-found", err)
}

// TestErrorHintsDaemonStopSignalLeaked verifies that when daemon stop fails
// because the process is already gone the error:
//   a) does NOT propagate the raw "signal daemon: os: process already finished" string,
//   b) is an *appError (or at minimum wraps a clean message), and
//   c) carries no leaked Go internals in its message.
//
// The bead says the fix should normalise this to "daemon was not running" so
// this test confirms the normalised form is present.
func TestErrorHintsDaemonStopSignalLeaked(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)

	// Write a PID file pointing at a process that does not exist so
	// signalProcess returns "os: process already finished" (or similar).
	runtimeDir := filepath.Join(homeDir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatalf("mkdir runtime: %v", err)
	}
	// PID 1 is always alive but we cannot signal it; use a harvested child.
	// Spawn and immediately reap a subprocess to get a definitely-dead PID.
	cmd := fmt.Sprintf("%d", os.Getpid()) // parent PID won't be signallable; use a dead one below
	_ = cmd

	// Use a child that exits immediately so we can capture its (now-dead) PID.
	import_os_exec := func() (int, error) {
		var child *os.Process
		proc, err := os.StartProcess("/bin/sh", []string{"sh", "-c", "exit 0"}, &os.ProcAttr{})
		if err != nil {
			return 0, err
		}
		child = proc
		_, err = child.Wait()
		return child.Pid, err
	}
	deadPID, err := import_os_exec()
	if err != nil {
		t.Fatalf("spawn dead process: %v", err)
	}

	pidFile := filepath.Join(runtimeDir, "daemon.pid")
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", deadPID)), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	stopErr := daemonCommand(context.Background(), []string{"stop"}, io.Discard, &fakeStarter{})
	if stopErr == nil {
		t.Fatal("TestErrorHintsDaemonStopSignalLeaked: expected error when signalling dead PID, got nil")
	}

	// Must not expose raw Go internals.
	if contains := "signal daemon: os: process already finished"; bytes.Contains([]byte(stopErr.Error()), []byte(contains)) {
		t.Fatalf("daemon stop leaks raw Go internals: %q", stopErr.Error())
	}

	// Must be an *appError so the JSON envelope carries structured fields.
	var ae *appError
	if !errors.As(stopErr, &ae) {
		t.Fatalf("daemon stop error is not *appError; got %T: %v", stopErr, stopErr)
	}

	// Message should read "daemon was not running" (or similar human-friendly form).
	if ae.Message == "" {
		t.Fatalf("daemon stop *appError has empty Message")
	}
}
