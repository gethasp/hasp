package app

// RED tests for hasp-t7sq — `hasp proof` collapses the 200+ char first-proof
// one-liner from quickstart.md into a single command. Contract pinned:
//
//   - Required: --secret <name|alias>; uses sensible defaults for the rest
//     (--grant-project window, --grant-secret session, --grant-window 15m).
//   - On success: prints "PASS" and a short summary; exits 0.
//   - On failure: prints "FAIL" and a reason; exits non-zero.
//   - --secret missing → usage error (fail-closed); no implicit pick.
//   - `help proof` is registered.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestProofCommandReportsPassWhenSecretIsBound(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "sk-proof-fixture"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "api_token=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}

	var stdout bytes.Buffer
	if err := proofCommand(context.Background(), []string{
		"--project-root", projectRoot,
		"--secret", "api_token",
	}, &stdout, io.Discard, starter); err != nil {
		t.Fatalf("proof: %v\nstdout=%s", err, stdout.String())
	}
	if !strings.Contains(stdout.String(), "PASS") {
		t.Fatalf("expected PASS in stdout, got %q", stdout.String())
	}
	// Defense in depth: the secret value must never appear in the proof output.
	if strings.Contains(stdout.String(), "sk-proof-fixture") {
		t.Fatalf("proof output leaked secret value: %q", stdout.String())
	}
}

func TestProofCommandFailsWhenSecretMissing(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}

	// Reference a secret name that does not exist in the vault — proof must
	// fail closed with a non-nil error and surface "FAIL" on stdout so the
	// quickstart user sees what happened.
	var stdout bytes.Buffer
	err := proofCommand(context.Background(), []string{
		"--project-root", projectRoot,
		"--secret", "nonexistent_secret",
	}, &stdout, io.Discard, starter)
	if err == nil {
		t.Fatal("expected proof to fail when secret is missing")
	}
	if !strings.Contains(stdout.String(), "FAIL") {
		t.Fatalf("expected FAIL marker in stdout, got %q (err=%v)", stdout.String(), err)
	}
}

func TestProofCommandJSONFailureDoesNotPrintHumanFail(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}

	ctx := contextWithGlobalFlags(context.Background(), globalFlags{json: true})
	var stdout bytes.Buffer
	err := proofCommand(ctx, []string{
		"--project-root", projectRoot,
		"--secret", "nonexistent_secret",
	}, &stdout, io.Discard, starter)
	if err == nil {
		t.Fatal("expected proof to fail when secret is missing")
	}
	if stdout.Len() != 0 {
		t.Fatalf("JSON proof failure must not print human FAIL to stdout, got %q", stdout.String())
	}
}

func TestProofCommandRequiresSecretFlag(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := proofCommand(context.Background(), []string{}, io.Discard, io.Discard, starter); err == nil {
		t.Fatal("expected error when --secret is missing")
	}
}

func TestProofHelpRegistered(t *testing.T) {
	lockAppSeams(t)
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"help", "proof"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("help proof: %v", err)
	}
	if !strings.Contains(out.String(), "proof") {
		t.Fatalf("help proof output missing 'proof': %q", out.String())
	}
}
