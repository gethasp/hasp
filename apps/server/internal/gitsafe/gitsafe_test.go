package gitsafe

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestBuildCommandPrependsSafeFlagsAndKeepsCallerArgsAfter checks the order
// hasp-qyt requires: the hardening flags must come BEFORE the user-supplied
// subcommand args so that a repo-side override cannot then re-enable hooks.
func TestBuildCommandPrependsSafeFlagsAndKeepsCallerArgsAfter(t *testing.T) {
	cmd := BuildCommand(context.Background(), "/tmp/proj", "rev-parse", "--show-toplevel")

	args := cmd.Args
	if len(args) == 0 || args[0] != "git" {
		t.Fatalf("expected argv[0]=git, got %v", args)
	}
	flagsJoined := strings.Join(args, " ")
	for _, must := range []string{
		"-c core.hooksPath=/dev/null",
		"-c safe.directory=*",
	} {
		if !strings.Contains(flagsJoined, must) {
			t.Fatalf("BuildCommand argv missing %q; full argv=%v", must, args)
		}
	}

	idxC := indexOf(args, "-C")
	idxRev := indexOf(args, "rev-parse")
	if idxC == -1 || idxRev == -1 {
		t.Fatalf("argv missing -C or rev-parse: %v", args)
	}
	if args[idxC+1] != "/tmp/proj" {
		t.Fatalf("-C value = %q, want /tmp/proj", args[idxC+1])
	}
	idxHooks := indexOf(args, "core.hooksPath=/dev/null")
	if idxHooks == -1 || idxHooks > idxRev {
		t.Fatalf("core.hooksPath=/dev/null must appear before rev-parse; argv=%v", args)
	}
}

// TestBuildCommandSetsScrubbedEnvWithoutInheritedGitVars locks in that the
// command starts from an empty env (PATH-only) plus our safe overrides, so
// stray GIT_DIR / GIT_WORK_TREE / GIT_CONFIG vars in the parent process do
// not leak into the child.
func TestBuildCommandSetsScrubbedEnvWithoutInheritedGitVars(t *testing.T) {
	t.Setenv("GIT_DIR", "/should/not/leak")
	t.Setenv("GIT_WORK_TREE", "/should/not/leak")
	t.Setenv("GIT_CONFIG", "/should/not/leak")

	cmd := BuildCommand(context.Background(), "/tmp/proj", "rev-parse", "--show-toplevel")

	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "GIT_DIR=") || strings.HasPrefix(kv, "GIT_WORK_TREE=") || strings.HasPrefix(kv, "GIT_CONFIG=") {
			t.Fatalf("scrubbed env leaked %q from parent; full env=%v", kv, cmd.Env)
		}
	}
	mustEnv := []string{
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PAGER=cat",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	}
	for _, want := range mustEnv {
		if !envContains(cmd.Env, want) {
			t.Fatalf("BuildCommand env missing %q; got %v", want, cmd.Env)
		}
	}

	pathFound := false
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "PATH=") {
			pathFound = true
			break
		}
	}
	if !pathFound {
		t.Fatalf("BuildCommand env must preserve PATH so git can find subcommands; got %v", cmd.Env)
	}
}

func TestBuildCommandPreservesGitCeilingDirectories(t *testing.T) {
	t.Setenv("GIT_CEILING_DIRECTORIES", "/tmp/hasp-ceiling")

	cmd := BuildCommand(context.Background(), "/tmp/proj", "rev-parse", "--show-toplevel")

	if !envContains(cmd.Env, "GIT_CEILING_DIRECTORIES=/tmp/hasp-ceiling") {
		t.Fatalf("BuildCommand env must preserve GIT_CEILING_DIRECTORIES; got %v", cmd.Env)
	}
}

func TestBuildConfigCommandReadsUserConfigWithoutEnvInjectedConfig(t *testing.T) {
	t.Setenv("HOME", "/tmp/hasp-home")
	t.Setenv("GIT_CONFIG_GLOBAL", "/tmp/evil-global")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
	t.Setenv("GIT_CONFIG_VALUE_0", "/tmp/evil-hooks")

	cmd := buildConfigCommand(context.Background(), "/tmp/proj", "config", "--path", "--get", "core.hooksPath")

	argsJoined := strings.Join(cmd.Args, " ")
	if strings.Contains(argsJoined, "core.hooksPath=/dev/null") {
		t.Fatalf("config lookup must not disable core.hooksPath while reading it; argv=%v", cmd.Args)
	}
	if !strings.Contains(argsJoined, "-c safe.directory=*") {
		t.Fatalf("config lookup should keep safe.directory override; argv=%v", cmd.Args)
	}
	if !envContains(cmd.Env, "HOME=/tmp/hasp-home") {
		t.Fatalf("config lookup must preserve HOME so normal global git config is visible; env=%v", cmd.Env)
	}
	if !envContains(cmd.Env, "GIT_CONFIG_SYSTEM=/dev/null") {
		t.Fatalf("config lookup must ignore system git config; env=%v", cmd.Env)
	}
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "GIT_CONFIG_GLOBAL=") || strings.HasPrefix(kv, "GIT_CONFIG_COUNT=") {
			t.Fatalf("config lookup must scrub env-injected git config, leaked %q in %v", kv, cmd.Env)
		}
	}
}

// TestRevParseTopLevelAppliesFallbackTimeoutWhenContextHasNone ensures the
// helper always runs git under a deadline even when the caller passes an
// untimed context, so a hung git child cannot block the daemon.
func TestRevParseTopLevelAppliesFallbackTimeoutWhenContextHasNone(t *testing.T) {
	origCommandContext := commandContextFn
	defer func() { commandContextFn = origCommandContext }()

	var seenDeadline bool
	commandContextFn = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if _, ok := ctx.Deadline(); ok {
			seenDeadline = true
		}
		return exec.CommandContext(ctx, "true")
	}

	if _, err := RevParseTopLevel(context.Background(), "/tmp"); err != nil {
		t.Fatalf("RevParseTopLevel: %v", err)
	}
	if !seenDeadline {
		t.Fatal("RevParseTopLevel must apply DefaultTimeout when caller's ctx has no deadline")
	}
}

// TestRevParseTopLevelHonorsCallerDeadline ensures a caller who set their own
// deadline gets it preserved — we should not extend it.
func TestRevParseTopLevelHonorsCallerDeadline(t *testing.T) {
	origCommandContext := commandContextFn
	defer func() { commandContextFn = origCommandContext }()

	callerDeadline := time.Now().Add(7 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), callerDeadline)
	defer cancel()

	var seenDeadline time.Time
	commandContextFn = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		d, ok := ctx.Deadline()
		if ok {
			seenDeadline = d
		}
		return exec.CommandContext(ctx, "true")
	}

	_, _ = RevParseTopLevel(ctx, "/tmp")
	if seenDeadline.IsZero() || !seenDeadline.Equal(callerDeadline) {
		t.Fatalf("RevParseTopLevel must reuse caller's deadline; want %v got %v", callerDeadline, seenDeadline)
	}
}

func indexOf(slice []string, target string) int {
	for i, s := range slice {
		if s == target {
			return i
		}
	}
	return -1
}

func envContains(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}
