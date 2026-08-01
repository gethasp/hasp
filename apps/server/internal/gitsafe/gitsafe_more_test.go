package gitsafe

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigCommandEnvironmentIncludesAllowedUserConfigInputs(t *testing.T) {
	t.Setenv("PATH", "/bin:/usr/bin")
	t.Setenv("HOME", "/home/tester")
	t.Setenv("XDG_CONFIG_HOME", "/home/tester/.config")
	t.Setenv("XDG_CONFIG_DIRS", "/etc/xdg")
	t.Setenv("USERPROFILE", "C:/Users/tester")
	t.Setenv("GIT_CEILING_DIRECTORIES", "/workspace")

	cmd := buildConfigCommand(context.Background(), "/repo", "config", "--get", "core.hooksPath")
	env := strings.Join(cmd.Env, "\n")
	for _, want := range []string{
		"PATH=/bin:/usr/bin",
		"HOME=/home/tester",
		"XDG_CONFIG_HOME=/home/tester/.config",
		"XDG_CONFIG_DIRS=/etc/xdg",
		"USERPROFILE=C:/Users/tester",
		"GIT_CEILING_DIRECTORIES=/workspace",
		"GIT_CONFIG_SYSTEM=/dev/null",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("config command env missing %q:\n%s", want, env)
		}
	}
}

func TestCommonDirSuccessAndFailure(t *testing.T) {
	orig := commandContextFn
	t.Cleanup(func() { commandContextFn = orig })

	commonDir := filepath.Join(t.TempDir(), "repo", "..", "repo", ".git")
	commandContextFn = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "printf", "%s\n", commonDir)
	}
	got, err := CommonDir(context.Background(), "/repo")
	if err != nil {
		t.Fatalf("CommonDir success: %v", err)
	}
	if got != filepath.Clean(commonDir) {
		t.Fatalf("CommonDir = %q, want %q", got, filepath.Clean(commonDir))
	}

	commandContextFn = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "exit 2")
	}
	if _, err := CommonDir(context.Background(), "/repo"); err == nil || !strings.Contains(err.Error(), "git rev-parse --git-common-dir") {
		t.Fatalf("expected CommonDir git error, got %v", err)
	}
}

func TestCoreHooksPathSuccessMissingAndFailure(t *testing.T) {
	orig := commandContextFn
	t.Cleanup(func() { commandContextFn = orig })

	commandContextFn = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "printf", " .githooks \n")
	}
	got, ok, err := CoreHooksPath(context.Background(), "/repo")
	if err != nil {
		t.Fatalf("CoreHooksPath success: %v", err)
	}
	if !ok || got != ".githooks" {
		t.Fatalf("CoreHooksPath = (%q, %v), want (.githooks, true)", got, ok)
	}

	commandContextFn = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "exit 1")
	}
	got, ok, err = CoreHooksPath(context.Background(), "/repo")
	if err != nil || ok || got != "" {
		t.Fatalf("CoreHooksPath missing = (%q, %v, %v), want empty false nil", got, ok, err)
	}

	commandContextFn = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "exit 2")
	}
	if _, _, err := CoreHooksPath(context.Background(), "/repo"); err == nil || !strings.Contains(err.Error(), "git config --get core.hooksPath") {
		t.Fatalf("expected CoreHooksPath git error, got %v", err)
	}
}
