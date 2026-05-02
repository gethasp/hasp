package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hasp-a7xd: stable error codes and a documented exit-code bucket table.
// Codes flow through the structured-error envelope (hasp-ynci) and through
// the binary's exit code so scripts can branch on machine-readable failure.

func TestAppErrorExitCodeBuckets(t *testing.T) {
	cases := []struct {
		code string
		want int
	}{
		{errCodeUserInput, 2},
		{errCodeNotInRepo, 2},
		{errCodePermission, 3},
		{errCodeGrantDenied, 3},
		{errCodeVaultLocked, 3},
		{errCodePasswordWrong, 3},
		{errCodeDaemonUnreachable, 4},
		{errCodeRepoLeak, 5},
		{errCodeInternal, 1},
		{"E_UNKNOWN_TO_REGISTRY", 1},
	}
	for _, tc := range cases {
		got := appErrorExitCode(newAppError(tc.code, "msg"))
		if got != tc.want {
			t.Errorf("exit code for %s: got %d, want %d", tc.code, got, tc.want)
		}
	}
}

func TestAppErrorExitCodePlainErrorReturnsOne(t *testing.T) {
	if got := appErrorExitCode(errors.New("plain")); got != 1 {
		t.Errorf("plain error exit code: got %d, want 1", got)
	}
}

func TestAppErrorExitCodeNilReturnsZero(t *testing.T) {
	if got := appErrorExitCode(nil); got != 0 {
		t.Errorf("nil exit code: got %d, want 0", got)
	}
}

// TestCheckRepoLeakIsTaggedWithRepoLeakCode wires the canonical
// repo-leak detection error site through the new appError envelope so
// scripts can branch on E_REPO_LEAK.
func TestCheckRepoLeakIsTaggedWithRepoLeakCode(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	leakValue := "leaked-secret-aaaa-1111"
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", leakValue}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	leakPath := filepath.Join(projectRoot, "leaks.txt")
	if err := os.WriteFile(leakPath, []byte(leakValue), 0o600); err != nil {
		t.Fatalf("write leak: %v", err)
	}
	err := Run(context.Background(), []string{"check-repo", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected check-repo to fail on detected leak")
	}
	envelope, ok := err.(*appError)
	if !ok {
		t.Fatalf("expected *appError envelope, got %T: %v", err, err)
	}
	if envelope.Code != errCodeRepoLeak {
		t.Fatalf("error code = %q, want %q", envelope.Code, errCodeRepoLeak)
	}
	if !strings.Contains(envelope.Message, "managed") {
		t.Fatalf("message %q does not mention 'managed'", envelope.Message)
	}
}
