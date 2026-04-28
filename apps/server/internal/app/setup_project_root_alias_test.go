package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// hasp-uxcn: --project-root is the canonical setup flag (matches run, inject,
// secret, etc.); --repo remains as a deprecated alias.

func TestParseSetupOptionsAcceptsProjectRoot(t *testing.T) {
	opts, repoFlagUsed, err := parseSetupOptions([]string{
		"--non-interactive",
		"--hasp-home", "/tmp/hasp-home",
		"--project-root", "/tmp/proj",
		"--agent", "codex-cli",
		"--master-password-env", "PW",
	})
	if err != nil {
		t.Fatalf("parseSetupOptions: %v", err)
	}
	if repoFlagUsed {
		t.Fatalf("did not expect --repo deprecation flag with --project-root")
	}
	if opts.Repo != "/tmp/proj" {
		t.Fatalf("expected canonical Repo == /tmp/proj, got %q", opts.Repo)
	}
}

func TestParseSetupOptionsTreatsRepoAsDeprecatedAlias(t *testing.T) {
	opts, repoFlagUsed, err := parseSetupOptions([]string{
		"--non-interactive",
		"--hasp-home", "/tmp/hasp-home",
		"--repo", "/tmp/legacy",
		"--agent", "codex-cli",
		"--master-password-env", "PW",
	})
	if err != nil {
		t.Fatalf("parseSetupOptions: %v", err)
	}
	if !repoFlagUsed {
		t.Fatalf("expected --repo to be flagged as deprecated alias")
	}
	if opts.Repo != "/tmp/legacy" {
		t.Fatalf("expected --repo path to populate Repo, got %q", opts.Repo)
	}
}

func TestParseSetupOptionsRejectsMixedRepoAndProjectRoot(t *testing.T) {
	if _, _, err := parseSetupOptions([]string{
		"--repo", "/tmp/a",
		"--project-root", "/tmp/b",
	}); err == nil {
		t.Fatal("expected error when --repo and --project-root point at different paths")
	}
}

// Setup integration: --repo emits a deprecation warning that --quiet
// suppresses (matches the rest of the deprecation regime in hasp-y78u).
func TestSetupCommandDeprecationWarningUnderRepoAlias(t *testing.T) {
	// We intentionally drive parseSetupOptions through the setupCommand
	// shim and let it fail at runSetup; the deprecation print should
	// happen between parse and runSetup so we can capture stderr without
	// completing a full setup flow.
	var stderr bytes.Buffer
	_ = setupCommand(context.Background(), []string{
		"--non-interactive",
		"--hasp-home", "/dev/null/hasp-home",
		"--repo", "/tmp/legacy-deprecated",
		"--master-password-env", "HASP_NONEXISTENT_PW",
	}, nil, &bytes.Buffer{}, &stderr)
	if !strings.Contains(stderr.String(), "deprecated") || !strings.Contains(stderr.String(), "--project-root") {
		t.Fatalf("expected deprecation warning naming --project-root, got %q", stderr.String())
	}
}
