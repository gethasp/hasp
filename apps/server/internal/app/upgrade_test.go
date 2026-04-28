package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/release"
)

func newPinnedKeyForTest(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub
}

func TestUpgradeCommandRequiresVersionFlag(t *testing.T) {
	t.Setenv("HASP_VERSION", "0.1.32")
	restore := release.SetPinnedKeysForTest(hex.EncodeToString(newPinnedKeyForTest(t)))
	defer restore()

	deps := defaultUpgradeDeps()
	err := upgradeCommandWithDeps(context.Background(), nil, bytes.NewReader(nil), io.Discard, io.Discard, deps)
	if err == nil || !strings.Contains(err.Error(), "--version is required") {
		t.Fatalf("expected --version required, got %v", err)
	}
}

func TestUpgradeCommandRefusesWithoutPinnedKeys(t *testing.T) {
	t.Setenv("HASP_VERSION", "0.1.32")
	restore := release.SetPinnedKeysForTest("")
	defer restore()

	deps := defaultUpgradeDeps()
	err := upgradeCommandWithDeps(context.Background(), []string{"--version", "0.2.0", "--yes"}, bytes.NewReader(nil), io.Discard, io.Discard, deps)
	if err == nil || !strings.Contains(err.Error(), "no embedded release-signing keys") {
		t.Fatalf("expected no-pinned-keys error, got %v", err)
	}
}

func TestUpgradeCommandRefusesDowngrade(t *testing.T) {
	t.Setenv("HASP_VERSION", "0.2.0")
	restore := release.SetPinnedKeysForTest(hex.EncodeToString(newPinnedKeyForTest(t)))
	defer restore()

	deps := defaultUpgradeDeps()
	err := upgradeCommandWithDeps(context.Background(), []string{"--version", "0.1.32", "--yes"}, bytes.NewReader(nil), io.Discard, io.Discard, deps)
	if !errors.Is(err, release.ErrDowngrade) {
		t.Fatalf("expected ErrDowngrade, got %v", err)
	}
}

func TestUpgradeCommandRefusesNonInteractiveWithoutYes(t *testing.T) {
	t.Setenv("HASP_VERSION", "0.1.32")
	restore := release.SetPinnedKeysForTest(hex.EncodeToString(newPinnedKeyForTest(t)))
	defer restore()

	deps := defaultUpgradeDeps()
	deps.IsTerminal = func() bool { return false }
	deps.Executable = func() (string, error) { return "/usr/local/bin/hasp", nil }

	err := upgradeCommandWithDeps(context.Background(), []string{"--version", "0.2.0"}, bytes.NewReader(nil), io.Discard, io.Discard, deps)
	if err == nil || !strings.Contains(err.Error(), "non-interactively without --yes") {
		t.Fatalf("expected non-interactive refusal, got %v", err)
	}
}

func TestUpgradeCommandHappyPathYes(t *testing.T) {
	t.Setenv("HASP_VERSION", "0.1.32")
	restore := release.SetPinnedKeysForTest(hex.EncodeToString(newPinnedKeyForTest(t)))
	defer restore()

	dir := t.TempDir()
	exePath := filepath.Join(dir, "hasp")

	deps := defaultUpgradeDeps()
	deps.Executable = func() (string, error) { return exePath, nil }
	deps.IsTerminal = func() bool { return false }
	called := false
	deps.Upgrade = func(_ context.Context, opts release.UpgradeOptions) (release.UpgradeReport, error) {
		called = true
		if opts.TargetVersion != "0.2.0" {
			t.Errorf("TargetVersion = %q", opts.TargetVersion)
		}
		if opts.TargetPath != exePath {
			t.Errorf("TargetPath = %q", opts.TargetPath)
		}
		if opts.CurrentVersion != "0.1.32" {
			t.Errorf("CurrentVersion = %q", opts.CurrentVersion)
		}
		if len(opts.Pinned) == 0 {
			t.Error("Pinned not propagated")
		}
		return release.UpgradeReport{
			FromVersion: "0.1.32",
			ToVersion:   "0.2.0",
			SignerKey:   "abcdef1234567890deadbeefcafebabe0011223344",
			InstalledAt: exePath,
		}, nil
	}

	var stdout bytes.Buffer
	if err := upgradeCommandWithDeps(context.Background(), []string{"--version", "0.2.0", "--yes"}, bytes.NewReader(nil), &stdout, io.Discard, deps); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if !called {
		t.Fatal("expected release.Upgrade to be invoked")
	}
	if !strings.Contains(stdout.String(), "Upgraded 0.1.32 → 0.2.0") {
		t.Errorf("missing summary line: %q", stdout.String())
	}
}

func TestUpgradeCommandJSONOutput(t *testing.T) {
	t.Setenv("HASP_VERSION", "0.1.32")
	restore := release.SetPinnedKeysForTest(hex.EncodeToString(newPinnedKeyForTest(t)))
	defer restore()

	dir := t.TempDir()
	exePath := filepath.Join(dir, "hasp")

	deps := defaultUpgradeDeps()
	deps.Executable = func() (string, error) { return exePath, nil }
	deps.IsTerminal = func() bool { return false }
	deps.Upgrade = func(_ context.Context, _ release.UpgradeOptions) (release.UpgradeReport, error) {
		return release.UpgradeReport{
			FromVersion: "0.1.32",
			ToVersion:   "0.2.0",
			SignerKey:   "abcdef1234567890deadbeefcafebabe0011223344",
			InstalledAt: exePath,
		}, nil
	}

	var stdout bytes.Buffer
	if err := upgradeCommandWithDeps(context.Background(), []string{"--version", "0.2.0", "--yes", "--json"}, bytes.NewReader(nil), &stdout, io.Discard, deps); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{`"from_version"`, `"to_version"`, `"signer_key"`, `"0.1.32"`, `"0.2.0"`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON missing %q in:\n%s", want, out)
		}
	}
}

func TestUpgradeCommandInteractiveDeclineAborts(t *testing.T) {
	t.Setenv("HASP_VERSION", "0.1.32")
	restore := release.SetPinnedKeysForTest(hex.EncodeToString(newPinnedKeyForTest(t)))
	defer restore()

	dir := t.TempDir()
	exePath := filepath.Join(dir, "hasp")

	deps := defaultUpgradeDeps()
	deps.Executable = func() (string, error) { return exePath, nil }
	deps.IsTerminal = func() bool { return true }
	upgradeCalled := false
	deps.Upgrade = func(context.Context, release.UpgradeOptions) (release.UpgradeReport, error) {
		upgradeCalled = true
		return release.UpgradeReport{}, nil
	}

	var stderr bytes.Buffer
	err := upgradeCommandWithDeps(context.Background(), []string{"--version", "0.2.0"}, strings.NewReader("n\n"), io.Discard, &stderr, deps)
	if err == nil || !strings.Contains(err.Error(), "aborted by user") {
		t.Fatalf("expected user abort, got %v", err)
	}
	if upgradeCalled {
		t.Fatal("Upgrade must not run after a 'n' answer")
	}
	if !strings.Contains(stderr.String(), "hasp upgrade plan") {
		t.Errorf("expected plan in stderr, got %q", stderr.String())
	}
}

func TestUpgradeCommandInteractiveAcceptInvokesUpgrade(t *testing.T) {
	t.Setenv("HASP_VERSION", "0.1.32")
	restore := release.SetPinnedKeysForTest(hex.EncodeToString(newPinnedKeyForTest(t)))
	defer restore()

	dir := t.TempDir()
	exePath := filepath.Join(dir, "hasp")

	deps := defaultUpgradeDeps()
	deps.Executable = func() (string, error) { return exePath, nil }
	deps.IsTerminal = func() bool { return true }
	deps.Upgrade = func(context.Context, release.UpgradeOptions) (release.UpgradeReport, error) {
		return release.UpgradeReport{
			FromVersion: "0.1.32",
			ToVersion:   "0.2.0",
			SignerKey:   "0011223344556677aabbccddeeff0099aabbccddee",
			InstalledAt: exePath,
		}, nil
	}

	var stdout bytes.Buffer
	if err := upgradeCommandWithDeps(context.Background(), []string{"--version", "0.2.0"}, strings.NewReader("y\n"), &stdout, io.Discard, deps); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if !strings.Contains(stdout.String(), "Upgraded") {
		t.Errorf("expected success line in stdout, got %q", stdout.String())
	}
}

func TestUpgradeCommandUnknownExtraArgs(t *testing.T) {
	t.Setenv("HASP_VERSION", "0.1.32")
	restore := release.SetPinnedKeysForTest(hex.EncodeToString(newPinnedKeyForTest(t)))
	defer restore()

	deps := defaultUpgradeDeps()
	err := upgradeCommandWithDeps(context.Background(), []string{"--version", "0.2.0", "stray"}, bytes.NewReader(nil), io.Discard, io.Discard, deps)
	if err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("expected usage error, got %v", err)
	}
}
