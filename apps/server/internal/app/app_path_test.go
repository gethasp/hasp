package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLauncherShellConfigPathVariants(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	origShell := appCurrentShellFn
	origHome := appUserHomeDirFn
	defer func() {
		appCurrentShellFn = origShell
		appUserHomeDirFn = origHome
	}()
	appUserHomeDirFn = func() (string, error) { return homeDir, nil }

	appCurrentShellFn = func() string { return "/bin/zsh" }
	if got, err := launcherShellConfigPath(); err != nil || got != filepath.Join(homeDir, ".zshrc") {
		t.Fatalf("zsh config path = %q err=%v", got, err)
	}

	appCurrentShellFn = func() string { return "/bin/bash" }
	if got, err := launcherShellConfigPath(); err != nil || got != filepath.Join(homeDir, ".bashrc") {
		t.Fatalf("bash config path = %q err=%v", got, err)
	}

	appCurrentShellFn = func() string { return "/opt/homebrew/bin/fish" }
	if got, err := launcherShellConfigPath(); err != nil || got != filepath.Join(homeDir, ".config", "fish", "config.fish") {
		t.Fatalf("fish config path = %q err=%v", got, err)
	}

	appCurrentShellFn = func() string { return "/bin/sh" }
	if got, err := launcherShellConfigPath(); err != nil || got != filepath.Join(homeDir, ".profile") {
		t.Fatalf("default config path = %q err=%v", got, err)
	}

	appUserHomeDirFn = func() (string, error) { return "", os.ErrPermission }
	if _, err := launcherShellConfigPath(); err == nil {
		t.Fatal("expected launcherShellConfigPath home error")
	}
}

func TestEnsureLauncherDirOnPathWritesAndIsIdempotent(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	launcherDir := filepath.Join(homeDir, ".hasp", "bin")
	origShell := appCurrentShellFn
	origHome := appUserHomeDirFn
	origRead := appReadFileFn
	origWrite := appWriteFileFn
	origMkdir := appMkdirAllFn
	defer func() {
		appCurrentShellFn = origShell
		appUserHomeDirFn = origHome
		appReadFileFn = origRead
		appWriteFileFn = origWrite
		appMkdirAllFn = origMkdir
	}()
	appCurrentShellFn = func() string { return "/bin/zsh" }
	appUserHomeDirFn = func() (string, error) { return homeDir, nil }
	appReadFileFn = os.ReadFile
	appWriteFileFn = os.WriteFile
	appMkdirAllFn = os.MkdirAll
	t.Setenv("PATH", "")

	configPath, changed, err := ensureLauncherDirOnPath(launcherDir)
	if err != nil {
		t.Fatalf("ensureLauncherDirOnPath: %v", err)
	}
	if !changed {
		t.Fatal("expected path config to change on first write")
	}
	if configPath != filepath.Join(homeDir, ".zshrc") {
		t.Fatalf("unexpected config path %q", configPath)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config path: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, haspPathBlockStart) || !strings.Contains(text, launcherDir) {
		t.Fatalf("expected managed path block, got %q", text)
	}

	configPath, changed, err = ensureLauncherDirOnPath(launcherDir)
	if err != nil {
		t.Fatalf("ensureLauncherDirOnPath second call: %v", err)
	}
	if changed {
		t.Fatal("expected idempotent path config write")
	}
	if configPath != filepath.Join(homeDir, ".zshrc") {
		t.Fatalf("unexpected config path on second call %q", configPath)
	}
}

func TestUpsertPathBlockAndPathContainsDir(t *testing.T) {
	launcherDir := "/tmp/hasp/bin"
	shBlock := upsertPathBlock("", launcherDir, "zsh")
	if !strings.Contains(shBlock, "export PATH=") || !strings.Contains(shBlock, launcherDir) {
		t.Fatalf("unexpected sh path block %q", shBlock)
	}
	fishBlock := upsertPathBlock("", launcherDir, "fish")
	if !strings.Contains(fishBlock, "set -gx PATH") || !strings.Contains(fishBlock, launcherDir) {
		t.Fatalf("unexpected fish path block %q", fishBlock)
	}
	replaced := upsertPathBlock(haspPathBlockStart+"\nexport PATH=\"/old:$PATH\"\n"+haspPathBlockEnd+"\n", launcherDir, "zsh")
	if strings.Contains(replaced, "/old") || !strings.Contains(replaced, launcherDir) {
		t.Fatalf("expected path block replacement, got %q", replaced)
	}
	withTrailingNewline := upsertPathBlock("export FOO=1\n", launcherDir, "zsh")
	if !strings.Contains(withTrailingNewline, "export FOO=1\n\n"+haspPathBlockStart) {
		t.Fatalf("expected appended block after trailing newline, got %q", withTrailingNewline)
	}
	withoutTrailingNewline := upsertPathBlock("export FOO=1", launcherDir, "zsh")
	if !strings.Contains(withoutTrailingNewline, "export FOO=1\n\n"+haspPathBlockStart) {
		t.Fatalf("expected appended block after missing trailing newline, got %q", withoutTrailingNewline)
	}
	if !pathContainsDir("/usr/bin:"+launcherDir, launcherDir) {
		t.Fatal("expected PATH match")
	}
	if pathContainsDir("/usr/bin:/bin", launcherDir) {
		t.Fatal("expected PATH miss")
	}
}

func TestEnsureLauncherDirOnPathChoiceBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	launcherDir := filepath.Join(homeDir, ".hasp", "bin")
	origShell := appCurrentShellFn
	origHome := appUserHomeDirFn
	origRead := appReadFileFn
	origWrite := appWriteFileFn
	origMkdir := appMkdirAllFn
	origIsCharDevice := secretIsCharDeviceFn
	origCurrentShell := appCurrentShellFn
	defer func() {
		appCurrentShellFn = origShell
		appUserHomeDirFn = origHome
		appReadFileFn = origRead
		appWriteFileFn = origWrite
		appMkdirAllFn = origMkdir
		secretIsCharDeviceFn = origIsCharDevice
		appCurrentShellFn = origCurrentShell
	}()
	appCurrentShellFn = func() string { return "/bin/zsh" }
	appUserHomeDirFn = func() (string, error) { return homeDir, nil }
	appReadFileFn = os.ReadFile
	appWriteFileFn = os.WriteFile
	appMkdirAllFn = os.MkdirAll
	secretIsCharDeviceFn = func(*os.File) bool { return true }

	t.Setenv("PATH", launcherDir)
	result, err := ensureLauncherDirOnPathChoice(context.Background(), setupOptionalBool{}, nil, io.Discard, io.Discard, launcherDir)
	if err != nil || result.Changed {
		t.Fatalf("expected no-op when PATH already contains launcher dir, got %+v err=%v", result, err)
	}

	t.Setenv("PATH", "")
	noResult, err := ensureLauncherDirOnPathChoice(context.Background(), setupOptionalBool{set: true, value: false}, nil, io.Discard, io.Discard, launcherDir)
	if err != nil || noResult.Changed {
		t.Fatalf("expected explicit false no-op, got %+v err=%v", noResult, err)
	}

	yesResult, err := ensureLauncherDirOnPathChoice(context.Background(), setupOptionalBool{set: true, value: true}, nil, io.Discard, io.Discard, launcherDir)
	if err != nil || !yesResult.Changed {
		t.Fatalf("expected explicit true write, got %+v err=%v", yesResult, err)
	}

	promptFile, err := os.CreateTemp(t.TempDir(), "path-yes")
	if err != nil {
		t.Fatalf("create prompt file: %v", err)
	}
	if _, err := promptFile.WriteString("y\n"); err != nil {
		t.Fatalf("seed prompt file: %v", err)
	}
	if _, err := promptFile.Seek(0, 0); err != nil {
		t.Fatalf("rewind prompt file: %v", err)
	}
	var promptOut bytes.Buffer
	result, err = ensureLauncherDirOnPathChoice(context.Background(), setupOptionalBool{}, promptFile, &promptOut, &promptOut, filepath.Join(homeDir, ".other", "bin"))
	if err != nil || !result.Changed {
		t.Fatalf("expected interactive yes path update, got %+v err=%v", result, err)
	}
	if !strings.Contains(promptOut.String(), "Add "+filepath.Join(homeDir, ".other", "bin")+" to your shell PATH") {
		t.Fatalf("expected path prompt output, got %q", promptOut.String())
	}

	t.Setenv("SHELL", "/bin/zsh")
	appCurrentShellFn = origCurrentShell
	if appCurrentShellFn() != "/bin/zsh" {
		t.Fatalf("expected default current shell function to read env, got %q", appCurrentShellFn())
	}

	promptErrFile, err := os.CreateTemp(t.TempDir(), "path-error")
	if err != nil {
		t.Fatalf("create prompt error file: %v", err)
	}
	promptErrPath := promptErrFile.Name()
	if err := promptErrFile.Close(); err != nil {
		t.Fatalf("close prompt error file: %v", err)
	}
	closedPromptErrFile, err := os.Open(promptErrPath)
	if err != nil {
		t.Fatalf("reopen prompt error file: %v", err)
	}
	if err := closedPromptErrFile.Close(); err != nil {
		t.Fatalf("close reopened prompt error file: %v", err)
	}
	if _, err := ensureLauncherDirOnPathChoice(context.Background(), setupOptionalBool{}, closedPromptErrFile, io.Discard, io.Discard, filepath.Join(homeDir, ".error", "bin")); err == nil {
		t.Fatal("expected prompt read failure")
	}

	appUserHomeDirFn = func() (string, error) { return "", os.ErrPermission }
	if _, err := ensureLauncherDirOnPathChoice(context.Background(), setupOptionalBool{set: true, value: true}, nil, io.Discard, io.Discard, filepath.Join(homeDir, ".fail", "bin")); err == nil {
		t.Fatal("expected path choice helper error from home resolution")
	}
	appUserHomeDirFn = func() (string, error) { return homeDir, nil }
	appReadFileFn = func(string) ([]byte, error) { return nil, errors.New("read config fail") }
	if _, _, err := ensureLauncherDirOnPath(filepath.Join(homeDir, ".readfail", "bin")); err == nil || err.Error() != "read config fail" {
		t.Fatalf("expected config read failure, got %v", err)
	}
	appReadFileFn = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	appMkdirAllFn = func(string, os.FileMode) error { return errors.New("mkdir config fail") }
	if _, _, err := ensureLauncherDirOnPath(filepath.Join(homeDir, ".mkdirfail", "bin")); err == nil || err.Error() != "mkdir config fail" {
		t.Fatalf("expected config mkdir failure, got %v", err)
	}
	appMkdirAllFn = os.MkdirAll
	appWriteFileFn = func(string, []byte, os.FileMode) error { return errors.New("write config fail") }
	if _, _, err := ensureLauncherDirOnPath(filepath.Join(homeDir, ".writefail", "bin")); err == nil || err.Error() != "write config fail" {
		t.Fatalf("expected config write failure, got %v", err)
	}
}
