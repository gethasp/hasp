package app

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hasp-b8zq: a 'window' scope grant must come with an explicit --grant-window
// duration. Silent 15m defaults can hand an unwitting user 15 minutes of
// future secret access they never asked for.

func TestValidateGrantWindowRequiresDurationForWindowScope(t *testing.T) {
	cases := []struct {
		name             string
		projectGrant     string
		secretGrant      string
		convenienceGrant string
		window           time.Duration
		wantErrContains  string
	}{
		{
			name:            "secret window without duration errors",
			secretGrant:     "window",
			window:          0,
			wantErrContains: "--grant-window",
		},
		{
			name:            "project window without duration errors",
			projectGrant:    "window",
			window:          0,
			wantErrContains: "--grant-window",
		},
		{
			name:             "convenience window without duration errors",
			convenienceGrant: "window",
			window:           0,
			wantErrContains:  "--grant-window",
		},
		{
			name:        "secret window with duration is allowed",
			secretGrant: "window",
			window:      5 * time.Minute,
		},
		{
			name:        "secret once never requires window duration",
			secretGrant: "once",
			window:      0,
		},
		{
			name:        "secret session never requires window duration",
			secretGrant: "session",
			window:      0,
		},
		{
			name:   "no grant scopes at all is allowed",
			window: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGrantWindow(tc.projectGrant, tc.secretGrant, tc.convenienceGrant, tc.window)
			if tc.wantErrContains == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErrContains)
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("error %q missing fragment %q", err.Error(), tc.wantErrContains)
			}
		})
	}
}

// TestExecuteCommandRefusesWindowScopeWithoutDuration covers the run/inject
// wiring: window scope without --grant-window must error before the daemon is
// ever contacted.
func TestExecuteCommandRefusesWindowScopeWithoutDuration(t *testing.T) {
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
		"--grant-secret", "window",
		"--", "echo", "hi",
	}
	err := runCommand(context.Background(), args, io.Discard, io.Discard, starter)
	if err == nil {
		t.Fatal("expected window scope without --grant-window to error")
	}
	if !strings.Contains(err.Error(), "--grant-window") {
		t.Fatalf("error %q missing --grant-window guidance", err.Error())
	}
}

// TestValidateGrantWindowBoundaries covers negative, ceiling, and large-but-ok
// window durations. These tests are RED: they must fail until the production
// impl enforces the hard ceiling and rejects negative values.
func TestValidateGrantWindowBoundaries(t *testing.T) {
	const hardCeiling = 7 * 24 * time.Hour

	cases := []struct {
		name             string
		projectGrant     string
		secretGrant      string
		convenienceGrant string
		window           time.Duration
		wantErr          bool
		wantErrContains  []string
	}{
		// Rule 1: negative window always rejected (even with no window scope).
		{
			name:            "negative window no scope",
			window:          -1 * time.Minute,
			wantErr:         true,
			wantErrContains: []string{"--grant-window", "negative"},
		},
		{
			name:            "negative window with secret scope",
			secretGrant:     "window",
			window:          -5 * time.Minute,
			wantErr:         true,
			wantErrContains: []string{"--grant-window", "negative"},
		},
		// Rule 3: window strictly greater than hard ceiling rejected.
		{
			name:            "one second over ceiling rejected",
			secretGrant:     "window",
			window:          hardCeiling + time.Second,
			wantErr:         true,
			wantErrContains: []string{"--grant-window", "7d"},
		},
		{
			name:            "two weeks over ceiling rejected",
			secretGrant:     "window",
			window:          14 * 24 * time.Hour,
			wantErr:         true,
			wantErrContains: []string{"--grant-window", "7d"},
		},
		// Rule 5: boundary — exactly hardCeiling is accepted.
		{
			name:        "exactly ceiling accepted",
			secretGrant: "window",
			window:      hardCeiling,
			wantErr:     false,
		},
		// Rule 4: above soft cap (24h) but within hard ceiling accepted.
		{
			name:        "48h accepted",
			secretGrant: "window",
			window:      48 * time.Hour,
			wantErr:     false,
		},
		{
			name:        "100h accepted",
			secretGrant: "window",
			window:      100 * time.Hour,
			wantErr:     false,
		},
		// Rule 6: existing positive case still works.
		{
			name:        "5min with secret window still accepted",
			secretGrant: "window",
			window:      5 * time.Minute,
			wantErr:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGrantWindow(tc.projectGrant, tc.secretGrant, tc.convenienceGrant, tc.window)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			for _, fragment := range tc.wantErrContains {
				if !strings.Contains(err.Error(), fragment) {
					t.Fatalf("error %q missing fragment %q", err.Error(), fragment)
				}
			}
		})
	}
}

// TestWriteEnvCommandRefusesWindowScopeWithoutDuration covers write-env's
// wiring path.
func TestWriteEnvCommandRefusesWindowScopeWithoutDuration(t *testing.T) {
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
		"--output", filepath.Join(t.TempDir(), ".env"),
		"--env", "API_TOKEN=API_TOKEN",
		"--grant-project", "window",
	}
	err := writeEnvCommand(context.Background(), args, io.Discard, io.Discard, starter)
	if err == nil {
		t.Fatal("expected write-env window scope without --grant-window to error")
	}
	if !errors.Is(err, errGrantWindowMissing) && !strings.Contains(err.Error(), "--grant-window") {
		t.Fatalf("error %q missing --grant-window guidance", err.Error())
	}
}
