package app

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// hasp-fbw9: --grant-* values now accept a shape-dispatched form so the user
// can pass `--grant-secret 15m` instead of the awkward
// `--grant-secret window --grant-window 15m`. Bare scope words (`once`,
// `session`, `window`) still parse for back-compat, with `window` requiring a
// companion --grant-window duration via parseGrantWithFallback.

func TestParseGrantValueShape(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantScope store.GrantScope
		wantTTL   time.Duration
		wantErr   string
	}{
		{name: "empty leaves scope unset", input: "", wantScope: ""},
		{name: "once parses as scope only", input: "once", wantScope: store.GrantOnce},
		{name: "session parses as scope only", input: "session", wantScope: store.GrantSession},
		{name: "window bareword parses as scope only", input: "window", wantScope: store.GrantWindow},
		{name: "duration value picks window scope", input: "15m", wantScope: store.GrantWindow, wantTTL: 15 * time.Minute},
		{name: "compound duration parses", input: "1h30m", wantScope: store.GrantWindow, wantTTL: 90 * time.Minute},
		{name: "whitespace tolerated", input: "  10s  ", wantScope: store.GrantWindow, wantTTL: 10 * time.Second},
		{name: "garbage word errors", input: "permanent", wantErr: "unrecognized grant value"},
		{name: "zero duration rejected", input: "0s", wantErr: "must be positive"},
		{name: "negative duration rejected", input: "-1m", wantErr: "must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope, ttl, err := parseGrantValue(tc.input)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q missing %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if scope != tc.wantScope {
				t.Fatalf("scope: got %q want %q", scope, tc.wantScope)
			}
			if ttl != tc.wantTTL {
				t.Fatalf("ttl: got %v want %v", ttl, tc.wantTTL)
			}
		})
	}
}

// resolveGrant blends the new shape-dispatched value with the legacy
// --grant-window fallback. The fallback only applies when the user passed the
// bareword `window`; new-shape duration values must not be silently overridden
// by --grant-window because that would replicate the very ambiguity hasp-fbw9
// is closing.
func TestResolveGrantBlendsLegacyWindow(t *testing.T) {
	cases := []struct {
		name      string
		value     string
		fallback  time.Duration
		wantScope store.GrantScope
		wantTTL   time.Duration
		wantErr   string
	}{
		{name: "window bareword adopts fallback", value: "window", fallback: 5 * time.Minute, wantScope: store.GrantWindow, wantTTL: 5 * time.Minute},
		{name: "duration value ignores fallback when fallback is zero", value: "15m", fallback: 0, wantScope: store.GrantWindow, wantTTL: 15 * time.Minute},
		{name: "duration plus fallback conflicts", value: "15m", fallback: 1 * time.Hour, wantErr: "conflict"},
		{name: "once with fallback is fine", value: "once", fallback: 5 * time.Minute, wantScope: store.GrantOnce},
		{name: "empty with fallback yields no grant", value: "", fallback: 5 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope, ttl, err := resolveGrant(tc.value, tc.fallback)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if scope != tc.wantScope {
				t.Fatalf("scope: got %q want %q", scope, tc.wantScope)
			}
			if ttl != tc.wantTTL {
				t.Fatalf("ttl: got %v want %v", ttl, tc.wantTTL)
			}
		})
	}
}

// TestExecuteCommandAcceptsDurationShapeGrant ensures --grant-secret 15m
// (without --grant-window) is wired through executeCommand.
func TestExecuteCommandAcceptsDurationShapeGrant(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	starter := newDaemonTestStarter(t)
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	args := []string{
		"--project-root", filepath.Clean(projectRoot),
		"--env", "API_TOKEN=API_TOKEN",
		"--grant-secret", "15m",
		"--", "echo", "hi",
	}
	// Should not error on flag validation (the underlying daemon path may
	// still error because nothing is captured, but we explicitly check that
	// the error is NOT the --grant-window guidance.)
	err := runCommand(context.Background(), args, io.Discard, io.Discard, starter)
	if err != nil && strings.Contains(err.Error(), "--grant-window duration is required") {
		t.Fatalf("duration-shaped grant should not require --grant-window; got %v", err)
	}
}

// TestExecuteCommandRejectsDurationPlusGrantWindow guards the new conflict:
// `--grant-secret 15m --grant-window 1h` is ambiguous.
func TestExecuteCommandRejectsDurationPlusGrantWindow(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	starter := newDaemonTestStarter(t)
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	args := []string{
		"--project-root", filepath.Clean(projectRoot),
		"--env", "API_TOKEN=API_TOKEN",
		"--grant-secret", "15m",
		"--grant-window", "1h",
		"--", "echo", "hi",
	}
	err := runCommand(context.Background(), args, io.Discard, io.Discard, starter)
	if err == nil {
		t.Fatal("expected duration value + --grant-window to conflict")
	}
	if !strings.Contains(err.Error(), "conflict") && !errors.Is(err, errGrantWindowConflict) {
		t.Fatalf("expected grant-window conflict error, got %v", err)
	}
}
