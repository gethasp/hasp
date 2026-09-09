package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/reposcan"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestCheckRepoPrePushReadsCommandInputAndBlocksHistory(t *testing.T) {
	lockAppSeams(t)
	root := t.TempDir()
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "synthetic push test password")
	for _, args := range [][]string{{"init"}, {"set", "--name", "push_token", "--value", "synthetic-outgoing-token"}} {
		if err := Run(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) string {
		t.Helper()
		out, err := run("git", append([]string{"-C", root, "-c", "core.hooksPath=/dev/null"}, args...)...)
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init")
	git("config", "user.name", "Test")
	git("config", "user.email", "test@example.com")
	path := filepath.Join(root, "token")
	if err := os.WriteFile(path, []byte("synthetic-outgoing-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "token")
	git("commit", "-m", "leak")
	if err := os.WriteFile(path, []byte("cleaned"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "token")
	git("commit", "-m", "clean")
	tip := git("rev-parse", "HEAD")
	input := "HEAD " + tip + " refs/heads/main " + strings.Repeat("0", len(tip)) + "\n"
	var out bytes.Buffer
	err := Run(context.Background(), []string{"check-repo", "--pre-push", "--project-root", root, "--json"}, strings.NewReader(input), &out, io.Discard)
	if err == nil {
		t.Fatalf("outgoing history was accepted: %s", out.String())
	}
	var result reposcan.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Walker != "git-outgoing" || len(result.Matches) != 1 || result.Matches[0].ItemName != "push_token" {
		t.Fatalf("outgoing scan did not use supplied stdin: %+v", result)
	}
}

func TestCheckRepoPrePushDeletionDoesNotRequireVault(t *testing.T) {
	lockAppSeams(t)
	root := t.TempDir()
	origOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = origOpen })
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		t.Error("no-content push attempted to unlock vault")
		return nil, store.ErrKeyringUnavailable
	}
	for _, input := range []string{"", "(delete) " + strings.Repeat("0", 40) + " refs/heads/main " + strings.Repeat("a", 40) + "\n"} {
		var out bytes.Buffer
		if err := Run(context.Background(), []string{"check-repo", "--pre-push", "--project-root", root, "--json"}, strings.NewReader(input), &out, io.Discard); err != nil {
			t.Fatalf("empty/deletion push failed: %v", err)
		}
		var result reposcan.Result
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Walker != "git-outgoing" {
			t.Fatalf("unexpected scan: %s", out.String())
		}
	}
}

func TestCheckRepoPrePushRejectsInvalidInputBeforeVault(t *testing.T) {
	lockAppSeams(t)
	origOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = origOpen })
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		t.Error("invalid push input attempted to unlock vault")
		return nil, errors.New("vault")
	}
	for _, args := range [][]string{{"check-repo", "--pre-push", "--staged"}, {"check-repo", "--pre-push", "--allow-managed-secrets"}} {
		if err := Run(context.Background(), args, strings.NewReader("malformed\n"), io.Discard, io.Discard); err == nil {
			t.Fatal("invalid push input passed")
		}
	}
}
