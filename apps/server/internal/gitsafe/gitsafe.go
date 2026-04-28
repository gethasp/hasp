// Package gitsafe wraps the small set of git invocations hasp performs so
// that a poisoned repo config (core.hooksPath, include.path, credential
// helpers) cannot use a routine path lookup like "rev-parse --show-toplevel"
// to execute arbitrary code in the daemon's context. Every call here uses
// hardened CLI flags, a scrubbed environment, and a timeout.
package gitsafe

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout caps each git invocation so a hung subprocess (network, lock
// file contention, ptrace ambush) cannot block the daemon indefinitely. The
// short bound reflects that hasp only invokes git for cheap, local-state
// queries — it does not fetch, push, or talk to remotes.
const DefaultTimeout = 5 * time.Second

// safeArgs are CLI overrides prepended to every git invocation. They neutralise
// the repo-side knobs that would otherwise let a hostile checkout direct git
// into running attacker-supplied programs:
//   - core.hooksPath=/dev/null disables any git hooks regardless of what the
//     repo or its included configs request.
//   - safe.directory=* lets git operate on paths the running uid does not own
//     without triggering the recent "dubious ownership" refusal, which is
//     necessary because hasp must work inside agents' workspaces.
//
// Note: the per-repo `.git/config`'s [include] path directive is still
// honored; -c include.path= would actually break parsing ("relative config
// includes must come from files"). The realistic bound on that surface is
// the DefaultTimeout and core.hooksPath override below — a malicious include
// can pull arbitrary key/values into git's config but not directly run code
// during a `rev-parse` invocation.
var safeArgs = []string{
	"-c", "core.hooksPath=/dev/null",
	"-c", "safe.directory=*",
}

// safeEnvOverrides force git off any interactive or credential-prompting code
// paths and ignore both global and system configs. Set after PATH so they
// always win. LC_ALL=C pins git's human-readable diagnostics to the canonical
// English so any stderr we ever surface (logs, ExitError.Stderr) stays
// locale-stable regardless of the operator's LANG.
var safeEnvOverrides = []string{
	"GIT_TERMINAL_PROMPT=0",
	"GIT_PAGER=cat",
	"GIT_OPTIONAL_LOCKS=0",
	"GIT_CONFIG_GLOBAL=/dev/null",
	"GIT_CONFIG_SYSTEM=/dev/null",
	"LC_ALL=C",
}

// pathFromEnv is the seam tests use to substitute a deterministic PATH.
var pathFromEnv = func() string { return os.Getenv("PATH") }

// commandContextFn is the seam tests use to intercept the constructed
// *exec.Cmd before it actually runs — production code uses exec.CommandContext.
var commandContextFn = exec.CommandContext

// BuildCommand constructs a hardened *exec.Cmd for the given git subcommand.
// Callers usually want RevParseTopLevel; BuildCommand is exported so future
// safe wrappers (rev-parse --git-dir, ls-files, etc.) can reuse the policy.
func BuildCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	full := make([]string, 0, len(safeArgs)+2+len(args))
	full = append(full, safeArgs...)
	if dir != "" {
		full = append(full, "-C", dir)
	}
	full = append(full, args...)
	cmd := commandContextFn(ctx, "git", full...)
	cmd.Env = buildSafeEnv()
	return cmd
}

func buildSafeEnv() []string {
	env := make([]string, 0, len(safeEnvOverrides)+1)
	if path := pathFromEnv(); path != "" {
		env = append(env, "PATH="+path)
	}
	env = append(env, safeEnvOverrides...)
	return env
}

// RevParseTopLevel runs `git rev-parse --show-toplevel` in dir under the
// hardened command policy and returns the trimmed top-level path. ctx is
// honored if it carries a deadline; otherwise DefaultTimeout is applied.
// The returned bytes match the historical contract: stdout including the
// trailing newline emitted by git, so callers that strings.TrimSpace it
// keep working unchanged.
func RevParseTopLevel(ctx context.Context, dir string) ([]byte, error) {
	ctx, cancel := withFallbackTimeout(ctx, DefaultTimeout)
	defer cancel()
	cmd := BuildCommand(ctx, dir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git rev-parse --show-toplevel: %w", err)
	}
	return out, nil
}

// TopLevel is a convenience wrapper that returns the trimmed string form,
// matching what hooks.gitTopLevel and store.CanonicalProjectRoot used to
// produce inline.
func TopLevel(ctx context.Context, dir string) (string, error) {
	out, err := RevParseTopLevel(ctx, dir)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func withFallbackTimeout(ctx context.Context, fallback time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, fallback)
}
