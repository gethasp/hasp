package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// TestCheckRepoRespectsGitignoreViaLsFiles locks in that check-repo uses
// `git ls-files --exclude-standard` to enumerate files, so a managed secret
// that lives ONLY inside a .gitignore'd path (e.g., node_modules/) is not
// reported. Otherwise check-repo turns into a two-minute OOM pass on any
// modern JS/Python project.
func TestCheckRepoRespectsGitignoreViaLsFiles(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	origEnsureSession := ensureSessionAppFn
	defer func() { ensureSessionAppFn = origEnsureSession }()
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "test-session"}, nil
	}

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123secret"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set api_token: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run project bind: %v", err)
	}

	if err := os.WriteFile(filepath.Join(projectRoot, ".gitignore"), []byte("node_modules/\nbuild/\n"), 0o600); err != nil {
		t.Fatalf("write gitignore: %v", err)
	}
	nodeModulesDir := filepath.Join(projectRoot, "node_modules", "pkg")
	if err := os.MkdirAll(nodeModulesDir, 0o700); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nodeModulesDir, "leak.js"), []byte("const t='abc123secret';"), 0o600); err != nil {
		t.Fatalf("write ignored leak: %v", err)
	}

	var out bytes.Buffer
	err := checkRepoCommand(context.Background(), []string{"--json", "--project-root", projectRoot}, &out, io.Discard)
	if err != nil {
		t.Fatalf("check-repo on gitignore-only leak must not error, got %v; body=%s", err, out.String())
	}
	if !strings.Contains(out.String(), "\"matches\":null") {
		t.Fatalf("check-repo must respect .gitignore; unexpected matches: %s", out.String())
	}
}

// TestCheckRepoDegradesWhenVaultCannotUnlock keeps managed repo hooks usable on
// machines where the keyring or vault is not currently available. The hook can
// still exercise the bounded file walker and reports that secret matching was
// skipped instead of blocking every commit/push before Git can proceed.
func TestCheckRepoDegradesWhenVaultCannotUnlock(t *testing.T) {
	lockAppSeams(t)
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "README.md"), []byte("clean\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	tests := []struct {
		name string
		err  error
	}{
		{name: "keyring unavailable", err: store.ErrKeyringUnavailable},
		{name: "vault not initialized", err: store.ErrVaultNotInitialized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origOpen := openVaultHandleFn
			t.Cleanup(func() { openVaultHandleFn = origOpen })
			openVaultHandleFn = func(context.Context) (*store.Handle, error) {
				return nil, fmt.Errorf("open vault: %w", tt.err)
			}

			var out bytes.Buffer
			if err := checkRepoCommand(context.Background(), []string{"--json", "--project-root", projectRoot}, &out, io.Discard); err != nil {
				t.Fatalf("check-repo should degrade when vault is unavailable, got %v; body=%s", err, out.String())
			}
			body := out.String()
			if !strings.Contains(body, `"matches":null`) || !strings.Contains(body, `"warning":"vault unavailable; managed-value matching was skipped"`) {
				t.Fatalf("expected degraded clean JSON response, got %s", body)
			}
		})
	}

	origOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = origOpen })
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		return nil, errors.New("vault storage corrupt")
	}
	if err := checkRepoCommand(context.Background(), []string{"--project-root", projectRoot}, io.Discard, io.Discard); err == nil {
		t.Fatal("expected unrelated vault errors to remain fatal")
	}
}

// TestCheckRepoDetectsBase64EncodedLeak locks in encoding-aware scanning
// (shares the matcher forms with redactor A8): a secret committed as base64
// must be flagged just like a raw occurrence.
func TestCheckRepoDetectsBase64EncodedLeak(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	origEnsureSession := ensureSessionAppFn
	defer func() { ensureSessionAppFn = origEnsureSession }()
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "test-session"}, nil
	}

	secret := []byte("abc123secret")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", string(secret)}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set api_token: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run project bind: %v", err)
	}

	encoded := base64.StdEncoding.EncodeToString(secret)
	leakPath := filepath.Join(projectRoot, "encoded.txt")
	if err := os.WriteFile(leakPath, []byte("opaque="+encoded+"\n"), 0o600); err != nil {
		t.Fatalf("write encoded leak: %v", err)
	}
	if out, err := run("git", "-C", projectRoot, "add", "-A"); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}

	var out bytes.Buffer
	err := checkRepoCommand(context.Background(), []string{"--json", "--project-root", projectRoot}, &out, io.Discard)
	if err == nil {
		t.Fatalf("check-repo must flag base64-encoded leak; body=%s", out.String())
	}
	if !strings.Contains(out.String(), "encoded.txt") {
		t.Fatalf("check-repo JSON must include encoded.txt path; body=%s", out.String())
	}
}

// TestCheckRepoSkipsOversizedFilesWithoutScanning locks in the per-file size
// cap: a multi-MiB file is skipped even if it contains the secret, because
// scanning arbitrary-size LFS/binary artefacts would OOM the daemon.
func TestCheckRepoSkipsOversizedFilesWithoutScanning(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	origEnsureSession := ensureSessionAppFn
	defer func() { ensureSessionAppFn = origEnsureSession }()
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "test-session"}, nil
	}

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123secret"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set api_token: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run project bind: %v", err)
	}

	origCap := checkRepoMaxBytes
	t.Cleanup(func() { checkRepoMaxBytes = origCap })
	checkRepoMaxBytes = 64

	leakPath := filepath.Join(projectRoot, "pack.bin")
	padding := bytes.Repeat([]byte{'x'}, 96)
	if err := os.WriteFile(leakPath, append(padding, []byte("abc123secret")...), 0o600); err != nil {
		t.Fatalf("write oversized file: %v", err)
	}
	if out, err := run("git", "-C", projectRoot, "add", "-A"); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}

	var out bytes.Buffer
	err := checkRepoCommand(context.Background(), []string{"--json", "--project-root", projectRoot}, &out, io.Discard)
	if err != nil {
		t.Fatalf("check-repo on oversized file must not error (it is skipped), got %v; body=%s", err, out.String())
	}
	if !strings.Contains(out.String(), "\"matches\":null") {
		t.Fatalf("oversized file must be skipped without producing a match, got %s", out.String())
	}
	if !strings.Contains(out.String(), "pack.bin") {
		t.Fatalf("skip must surface pack.bin in skipped[] so the operator knows a file was not scanned; body=%s", out.String())
	}
}

// TestCheckRepoFallsBackToWalkDirOutsideGitRepo ensures a directory that is
// not a git repo still scans (via filepath.WalkDir). Otherwise `hasp
// check-repo` would silently miss leaks in any not-yet-initialised project.
func TestCheckRepoFallsBackToWalkDirOutsideGitRepo(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	projectRoot := t.TempDir() // NOT a git repo
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	origEnsureSession := ensureSessionAppFn
	defer func() { ensureSessionAppFn = origEnsureSession }()
	ensureSessionAppFn = func(context.Context, brokerops.Connector, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "test-session"}, nil
	}

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "abc123secret"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set api_token: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--allow-non-git", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run project bind: %v", err)
	}

	leakPath := filepath.Join(projectRoot, "leak.txt")
	if err := os.WriteFile(leakPath, []byte("abc123secret"), 0o600); err != nil {
		t.Fatalf("write leak: %v", err)
	}

	var out bytes.Buffer
	err := checkRepoCommand(context.Background(), []string{"--json", "--project-root", projectRoot}, &out, io.Discard)
	if err == nil {
		t.Fatalf("check-repo non-git project must still flag leaks; body=%s", out.String())
	}
	if !strings.Contains(out.String(), "leak.txt") {
		t.Fatalf("check-repo must include leak.txt; body=%s", out.String())
	}
}
