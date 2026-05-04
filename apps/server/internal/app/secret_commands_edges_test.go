package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSecretHelperAndEdgeBranches(t *testing.T) {
	lockAppSeams(t)

	origCurrentUser := secretCurrentUserFn
	origExec := secretExecCommandFn
	origTTYExec := ttyutil.ExecCommandFn
	origClipboard := secretClipboardFn
	origIsCharDevice := secretIsCharDeviceFn
	origSetTTYEcho := secretSetTTYEchoFn
	origGetwd := secretGetwdFn
	origRuntimeGOOS := secretRuntimeGOOS
	origUpsert := secretUpsertItemFn
	origGetItem := secretGetItemFn
	origDeleteItem := secretDeleteItemFn
	origBindAlias := secretBindItemAliasFn
	origHideItem := secretHideItemFn
	origListItems := secretListItemsFn
	origExposures := secretItemExposuresFn
	defer func() {
		secretCurrentUserFn = origCurrentUser
		secretExecCommandFn = origExec
		ttyutil.ExecCommandFn = origTTYExec
		secretClipboardFn = origClipboard
		secretIsCharDeviceFn = origIsCharDevice
		secretSetTTYEchoFn = origSetTTYEcho
		secretGetwdFn = origGetwd
		secretRuntimeGOOS = origRuntimeGOOS
		secretUpsertItemFn = origUpsert
		secretGetItemFn = origGetItem
		secretDeleteItemFn = origDeleteItem
		secretBindItemAliasFn = origBindAlias
		secretHideItemFn = origHideItem
		secretListItemsFn = origListItems
		secretItemExposuresFn = origExposures
	}()

	t.Setenv("USER", "fallback-user")
	secretCurrentUserFn = func() (*user.User, error) { return nil, errors.New("no user") }
	if got := secretActorLabel(); got != "fallback-user" {
		t.Fatalf("secretActorLabel fallback = %q", got)
	}
	t.Setenv("USER", "")
	if got := secretActorLabel(); got != "unknown" {
		t.Fatalf("secretActorLabel unknown = %q", got)
	}

	if got := existingExposureReference(nil, "/tmp/repo"); got != "" {
		t.Fatalf("expected empty exposure ref, got %q", got)
	}
	if got := existingExposureReference([]store.ItemExposure{{ProjectRoot: "/tmp/repo", Reference: "secret_01"}}, "/tmp/repo"); got != "secret_01" {
		t.Fatalf("expected exposure ref match, got %q", got)
	}

	prompt := newSecretPrompt(bytes.NewBufferString("plain-value\n"), io.Discard, io.Discard)
	value, err := prompt.secretValue("EMAIL")
	if err != nil || string(value) != "plain-value" {
		t.Fatalf("unmasked secretValue = %q err=%v", string(value), err)
	}
	if _, err := newSecretPrompt(bytes.NewBuffer(nil), io.Discard, errWriter{err: errors.New("line fail")}).line("Label"); err == nil {
		t.Fatal("expected line write failure")
	}
	if _, err := newSecretPrompt(errReader{err: errors.New("read fail")}, io.Discard, io.Discard).line("Label"); err == nil {
		t.Fatal("expected line read failure")
	}
	if _, err := newSecretPrompt(bytes.NewBuffer(nil), io.Discard, errWriter{err: errors.New("value fail")}).secretValue("EMAIL"); err == nil {
		t.Fatal("expected secretValue line failure")
	}
	if _, err := newSecretPrompt(bytes.NewBuffer(nil), io.Discard, errWriter{err: errors.New("masked fail")}).secretValue("API_TOKEN"); err == nil {
		t.Fatal("expected masked secret prompt write failure")
	}

	if ok, err := newSecretPrompt(bytes.NewBufferString("\n"), io.Discard, io.Discard).confirm("Confirm", false); err != nil || ok {
		t.Fatalf("confirm default false = %v err=%v", ok, err)
	}
	if ok, err := newSecretPrompt(bytes.NewBufferString("yes\n"), io.Discard, io.Discard).confirm("Confirm", false); err != nil || !ok {
		t.Fatalf("confirm explicit yes = %v err=%v", ok, err)
	}
	if _, err := newSecretPrompt(errReader{err: errors.New("confirm fail")}, io.Discard, io.Discard).confirm("Confirm", true); err == nil {
		t.Fatal("expected confirm prompt failure")
	}

	choice, renamed, err := newSecretPrompt(bytes.NewBufferString("1\n"), io.Discard, io.Discard).collision("API_TOKEN")
	if err != nil || choice != "replace" || renamed != "" {
		t.Fatalf("collision replace = %q %q err=%v", choice, renamed, err)
	}
	choice, renamed, err = newSecretPrompt(bytes.NewBufferString("2\nRENAMED_TOKEN\n"), io.Discard, io.Discard).collision("API_TOKEN")
	if err != nil || choice != "rename" || renamed != "RENAMED_TOKEN" {
		t.Fatalf("collision rename = %q %q err=%v", choice, renamed, err)
	}
	choice, renamed, err = newSecretPrompt(bytes.NewBufferString("3\n"), io.Discard, io.Discard).collision("API_TOKEN")
	if err != nil || choice != "skip" {
		t.Fatalf("collision skip = %q %q err=%v", choice, renamed, err)
	}
	choice, renamed, err = newSecretPrompt(bytes.NewBufferString("9\n"), io.Discard, io.Discard).collision("API_TOKEN")
	if err != nil || choice != "cancel" {
		t.Fatalf("collision cancel = %q %q err=%v", choice, renamed, err)
	}
	if _, _, err := newSecretPrompt(bytes.NewBuffer(nil), io.Discard, errWriter{err: errors.New("collision write fail")}).collision("API_TOKEN"); err == nil {
		t.Fatal("expected collision write failure")
	}
	if choice, renamed, err := newSecretPrompt(bytes.NewBufferString("2\n"), io.Discard, io.Discard).collision("API_TOKEN"); err != nil || choice != "rename" || renamed != "" {
		t.Fatalf("expected empty rename result on EOF, got %q %q err=%v", choice, renamed, err)
	}

	if _, err := secretInputsFromArgs([]string{"=bad"}, newSecretPrompt(bytes.NewBuffer(nil), io.Discard, io.Discard)); err == nil {
		t.Fatal("expected empty-name arg parse failure")
	}
	if _, err := secretAddInputs(nil, newSecretPrompt(bytes.NewBufferString("\n"), io.Discard, io.Discard)); err == nil {
		t.Fatal("expected interactive add empty-name failure")
	}
	if _, err := secretUpdateInputs([]string{"UPDATED"}, newSecretPrompt(bytes.NewBufferString("value\n"), io.Discard, io.Discard)); err != nil {
		t.Fatalf("expected update inputs from args to succeed, got %v", err)
	}
	if _, err := secretUpdateInputs(nil, newSecretPrompt(errReader{err: errors.New("prompt fail")}, io.Discard, io.Discard)); err == nil {
		t.Fatal("expected interactive update prompt failure")
	}
	if inputs, err := secretUpdateInputs(nil, newSecretPrompt(bytes.NewBufferString("API_TOKEN\n"), io.Discard, io.Discard)); err != nil || len(inputs) != 1 || string(inputs[0].value) != "" {
		t.Fatalf("expected empty interactive update value on EOF, got %+v err=%v", inputs, err)
	}
	inputs, err := secretInputsFromArgs([]string{"PROMPTED"}, newSecretPrompt(bytes.NewBufferString("hidden\n"), io.Discard, io.Discard))
	if err != nil || len(inputs) != 1 || string(inputs[0].value) != "hidden" {
		t.Fatalf("prompted arg input = %+v err=%v", inputs, err)
	}
	inputs, err = secretUpdateInputs(nil, newSecretPrompt(bytes.NewBufferString("UPDATED_TOKEN\nnew-value\n"), io.Discard, io.Discard))
	if err != nil || len(inputs) != 1 || inputs[0].name != "UPDATED_TOKEN" {
		t.Fatalf("interactive update inputs = %+v err=%v", inputs, err)
	}
	if _, err := secretNameInputs(nil, newSecretPrompt(bytes.NewBufferString("\n"), io.Discard, io.Discard), "Key name"); err == nil {
		t.Fatal("expected interactive empty name failure")
	}
	if _, err := secretNameInputs(nil, newSecretPrompt(errReader{err: errors.New("name fail")}, io.Discard, io.Discard), "Key name"); err == nil {
		t.Fatal("expected secret name prompt failure")
	}
	if names, err := secretNameInputs([]string{"FIRST", "SECOND"}, newSecretPrompt(bytes.NewBuffer(nil), io.Discard, io.Discard), "Key name"); err != nil || len(names) != 2 {
		t.Fatalf("expected arg-based secret names, got %+v err=%v", names, err)
	}

	if value, err := newSecretPrompt(bytes.NewBufferString("stdin-secret\n"), io.Discard, io.Discard).readHidden(); err != nil || string(value) != "stdin-secret" {
		t.Fatalf("readHidden non-file = %q err=%v", string(value), err)
	}
	if got, ok := ttyutil.StdinFile(bytes.NewBuffer(nil)); ok || got != nil {
		t.Fatalf("expected stdinFile to reject non-file reader, got %v %v", got, ok)
	}
	tempFile, err := os.CreateTemp(t.TempDir(), "secret-input")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := tempFile.WriteString("file-secret\n"); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if _, err := tempFile.Seek(0, 0); err != nil {
		t.Fatalf("seek temp file: %v", err)
	}
	if got, ok := ttyutil.StdinFile(tempFile); !ok || got == nil {
		t.Fatalf("expected stdinFile to accept os.File, got %v %v", got, ok)
	}
	if value, err := newSecretPrompt(tempFile, io.Discard, io.Discard).readHidden(); err != nil || string(value) != "file-secret" {
		t.Fatalf("readHidden file fallback = %q err=%v", string(value), err)
	}

	secretIsCharDeviceFn = func(*os.File) bool { return true }
	secretSetTTYEchoFn = func(*os.File, bool) error { return errors.New("tty toggle failed") }
	if _, err := tempFile.Seek(0, 0); err != nil {
		t.Fatalf("seek temp file for tty toggle error: %v", err)
	}
	if value, err := newSecretPrompt(tempFile, io.Discard, io.Discard).readHidden(); err != nil || string(value) != "file-secret" {
		t.Fatalf("readHidden tty toggle failure fallback = %q err=%v", string(value), err)
	}

	ttyCalls := []bool{}
	secretSetTTYEchoFn = func(_ *os.File, enabled bool) error {
		ttyCalls = append(ttyCalls, enabled)
		return nil
	}
	if _, err := tempFile.Seek(0, 0); err != nil {
		t.Fatalf("seek temp file for tty success: %v", err)
	}
	if value, err := newSecretPrompt(tempFile, io.Discard, io.Discard).readHidden(); err != nil || string(value) != "file-secret" {
		t.Fatalf("readHidden tty path = %q err=%v", string(value), err)
	}
	if len(ttyCalls) != 2 || ttyCalls[0] || !ttyCalls[1] {
		t.Fatalf("unexpected tty toggle calls %+v", ttyCalls)
	}

	ttyCalls = nil
	if _, err := tempFile.Seek(0, 0); err != nil {
		t.Fatalf("seek temp file for print error: %v", err)
	}
	if _, err := newSecretPrompt(tempFile, io.Discard, errWriter{err: errors.New("stderr fail")}).readHidden(); err == nil {
		t.Fatal("expected readHidden print failure")
	}
	if ttyutil.IsCharDevice(nil) {
		t.Fatal("expected nil file not to be char device")
	}
	if ttyutil.IsCharDevice(tempFile) {
		t.Fatal("expected regular temp file not to be char device")
	}
	if err := tempFile.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	if ttyutil.IsCharDevice(tempFile) {
		t.Fatal("expected closed file stat failure to report non-char device")
	}
	if devNull, err := os.Open("/dev/null"); err == nil {
		defer devNull.Close()
		if !ttyutil.IsCharDevice(devNull) {
			t.Fatal("expected /dev/null to be treated as char device")
		}
	}

	clipboardScript := filepath.Join(t.TempDir(), "clipboard.sh")
	clipboardOutput := filepath.Join(t.TempDir(), "clipboard.out")
	if err := os.WriteFile(clipboardScript, []byte("#!/usr/bin/env bash\ncat > \""+clipboardOutput+"\"\n"), 0o755); err != nil {
		t.Fatalf("write clipboard script: %v", err)
	}
	secretRuntimeGOOS = "darwin"
	secretExecCommandFn = func(name string, args ...string) *exec.Cmd {
		return exec.Command(clipboardScript)
	}
	if err := copySecretToClipboard([]byte("copied-secret")); err != nil {
		t.Fatalf("copySecretToClipboard success: %v", err)
	}
	copied, err := os.ReadFile(clipboardOutput)
	if err != nil || string(copied) != "copied-secret" {
		t.Fatalf("unexpected copied output %q err=%v", string(copied), err)
	}

	failScript := filepath.Join(t.TempDir(), "clipboard-fail.sh")
	if err := os.WriteFile(failScript, []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("write clipboard fail script: %v", err)
	}
	secretExecCommandFn = func(name string, args ...string) *exec.Cmd {
		return exec.Command(failScript)
	}
	if err := copySecretToClipboard([]byte("copied-secret")); err == nil {
		t.Fatal("expected copySecretToClipboard failure")
	}
	secretRuntimeGOOS = "linux"
	secretExecCommandFn = func(name string, args ...string) *exec.Cmd {
		return exec.Command(clipboardScript)
	}
	if err := copySecretToClipboard([]byte("linux-secret")); err != nil {
		t.Fatalf("copySecretToClipboard linux path: %v", err)
	}
	secretExecCommandFn = func(name string, args ...string) *exec.Cmd {
		return exec.Command(failScript)
	}
	ttyutil.ExecCommandFn = func(name string, args ...string) *exec.Cmd {
		return exec.Command(failScript)
	}
	if err := ttyutil.SetTTYEcho(tempFile, true); err == nil {
		t.Fatal("expected SetTTYEcho true branch to fail on non-tty file")
	}

	if err := ttyutil.SetTTYEcho(tempFile, false); err == nil {
		t.Fatal("expected SetTTYEcho to fail on non-tty file")
	}

	secretGetwdFn = func() (string, error) { return "", errors.New("getwd fail") }
	if _, _, err := secretProjectContext(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "getwd fail") {
		t.Fatalf("expected getwd failure, got %v", err)
	}
	origCanon := appCanonicalProjectRootFn
	defer func() { appCanonicalProjectRootFn = origCanon }()
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) { return "", errors.New("canon fail") }
	if _, _, err := secretProjectContext(context.Background(), "/tmp/repo"); err == nil || !strings.Contains(err.Error(), "canon fail") {
		t.Fatalf("expected canonical root failure, got %v", err)
	}
}

func TestSecretCommandAndStoreEdgeBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}

	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	origGetwd := secretGetwdFn
	origClipboard := secretClipboardFn
	defer func() {
		secretGetwdFn = origGetwd
		secretClipboardFn = origClipboard
	}()
	secretGetwdFn = func() (string, error) { return projectRoot, nil }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	var directListOut bytes.Buffer
	if err := secretListCommand(context.Background(), []string{"--json"}, &directListOut); err != nil {
		t.Fatalf("direct secretListCommand: %v", err)
	}
	if !strings.Contains(directListOut.String(), "\"secrets\":[]") {
		t.Fatalf("expected direct empty list output, got %q", directListOut.String())
	}
	if err := secretListCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected secretListCommand parse error")
	}
	if err := secretListCommand(context.Background(), []string{"--json"}, errWriter{err: errors.New("list encode fail")}); err == nil {
		t.Fatal("expected secretListCommand encode failure")
	}

	var secretHelp bytes.Buffer
	if err := secretCommand(context.Background(), nil, bytes.NewBuffer(nil), &secretHelp, io.Discard); err != nil {
		t.Fatalf("expected secret command help, got %v", err)
	}
	if !strings.Contains(secretHelp.String(), "Work with the one local vault") {
		t.Fatalf("expected secret help output, got %q", secretHelp.String())
	}
	if err := secretCommand(context.Background(), []string{"bogus"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected unknown secret subcommand error")
	}

	var listOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "list", "--json"}, bytes.NewBuffer(nil), &listOut, &listOut); err != nil {
		t.Fatalf("secret list empty: %v", err)
	}
	if !strings.Contains(listOut.String(), "\"secrets\":[]") {
		t.Fatalf("expected empty secret list, got %q", listOut.String())
	}

	if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--expose=always", "API_TOKEN"}, bytes.NewBufferString("abc123\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault handle: %v", err)
	}
	secondProjectRoot := t.TempDir()
	if out, err := run("git", "-C", secondProjectRoot, "init"); err != nil {
		t.Fatalf("git init second project: %v: %s", err, out)
	}
	if _, _, autoCreated, err := ensureProjectBindingExplicit(context.Background(), handle, secondProjectRoot); err != nil || !autoCreated {
		t.Fatalf("expected explicit binding creation, got auto=%v err=%v", autoCreated, err)
	}
	if binding, _, autoCreated, err := ensureProjectBindingExplicit(context.Background(), handle, secondProjectRoot); err != nil || binding.ID == "" || autoCreated {
		t.Fatalf("expected explicit binding reuse, got %+v auto=%v err=%v", binding, autoCreated, err)
	}
	if err := secretAddCommand(context.Background(), []string{"--bad"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected secretAddCommand parse error")
	}
	if err := secretAddCommand(context.Background(), []string{"--vault-only", "TOKEN=value"}, bytes.NewBuffer(nil), errWriter{err: errors.New("add encode fail")}, io.Discard); err == nil {
		t.Fatal("expected secretAddCommand encode failure")
	}
	if err := Run(context.Background(), []string{"secret", "add", "API_TOKEN=other"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected add collision error")
	}

	renameInput := bytes.NewBufferString("rotated\n2\nAPI_TOKEN_ALT\n")
	if err := Run(context.Background(), []string{"secret", "add", "--expose=always", "API_TOKEN"}, renameInput, io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add rename collision: %v", err)
	}
	var revealAlt bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "get", "--reveal", "API_TOKEN_ALT"}, bytes.NewBuffer(nil), &revealAlt, &revealAlt); err != nil {
		t.Fatalf("secret get reveal alt: %v", err)
	}
	if strings.TrimSpace(revealAlt.String()) != "rotated" {
		t.Fatalf("unexpected alt reveal output %q", revealAlt.String())
	}

	if err := Run(context.Background(), []string{"secret", "update", "API_TOKEN"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret update: %v", err)
	}
	if err := secretUpdateCommand(context.Background(), []string{"--bad"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected secretUpdateCommand parse error")
	}
	if err := secretUpdateCommand(context.Background(), []string{"API_TOKEN=value"}, bytes.NewBuffer(nil), errWriter{err: errors.New("update encode fail")}, io.Discard); err == nil {
		t.Fatal("expected secretUpdateCommand encode failure")
	}
	if err := Run(context.Background(), []string{"secret", "get", "--reveal", "API_TOKEN", "API_TOKEN_ALT"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected multiple-name get failure")
	}
	if err := Run(context.Background(), []string{"secret", "get", "--reveal", "--copy", "API_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected mutually-exclusive get flags failure")
	}
	if err := secretGetCommand(context.Background(), []string{"--bad"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected secretGetCommand parse error")
	}
	if err := secretGetCommand(context.Background(), []string{"API_TOKEN"}, bytes.NewBuffer(nil), errWriter{err: errors.New("get encode fail")}, io.Discard); err == nil {
		t.Fatal("expected secretGetCommand encode failure")
	}

	copied := ""
	secretClipboardFn = func(value []byte) error {
		copied = string(value)
		return nil
	}
	var copyOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "get", "--copy", "API_TOKEN"}, bytes.NewBuffer(nil), &copyOut, &copyOut); err != nil {
		t.Fatalf("secret get copy: %v", err)
	}
	if copied != "value" {
		t.Fatalf("unexpected copied secret %q", copied)
	}
	secretClipboardFn = func([]byte) error { return errors.New("copy fail") }
	if err := Run(context.Background(), []string{"secret", "get", "--copy", "API_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected clipboard failure")
	}

	nonRepo := t.TempDir()
	secretGetwdFn = func() (string, error) { return nonRepo, nil }
	if err := Run(context.Background(), []string{"secret", "expose", "API_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected expose outside repo failure")
	}
	if err := Run(context.Background(), []string{"secret", "hide", "API_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected hide outside repo failure")
	}
	secretGetwdFn = func() (string, error) { return projectRoot, nil }

	if err := Run(context.Background(), []string{"secret", "hide", "API_TOKEN_ALT"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret hide once: %v", err)
	}
	var hideOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "hide", "API_TOKEN_ALT"}, bytes.NewBuffer(nil), &hideOut, &hideOut); err != nil {
		t.Fatalf("secret hide twice: %v", err)
	}
	if !strings.Contains(hideOut.String(), "already_hidden") {
		t.Fatalf("expected already_hidden output, got %q", hideOut.String())
	}
	if err := Run(context.Background(), []string{"secret", "expose", "MISSING_SECRET"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected missing secret expose failure")
	}
	var exposeOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "expose", "API_TOKEN"}, bytes.NewBuffer(nil), &exposeOut, &exposeOut); err != nil {
		t.Fatalf("secret expose existing: %v", err)
	}
	if !strings.Contains(exposeOut.String(), "already_exposed") {
		t.Fatalf("expected already_exposed output, got %q", exposeOut.String())
	}
	if err := secretExposeCommand(context.Background(), []string{"--bad"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected secretExposeCommand parse error")
	}
	if err := secretHideCommand(context.Background(), []string{"--bad"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected secretHideCommand parse error")
	}
	if err := secretDeleteCommand(context.Background(), []string{"--bad"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected secretDeleteCommand parse error")
	}
	if err := secretExposeCommand(context.Background(), []string{"API_TOKEN"}, bytes.NewBuffer(nil), errWriter{err: errors.New("expose encode fail")}, io.Discard); err == nil {
		t.Fatal("expected secretExposeCommand encode failure")
	}
	if err := secretHideCommand(context.Background(), []string{"API_TOKEN"}, bytes.NewBuffer(nil), errWriter{err: errors.New("hide encode fail")}, io.Discard); err == nil {
		t.Fatal("expected secretHideCommand encode failure")
	}
	if err := secretDeleteCommand(context.Background(), []string{"--yes", "API_TOKEN_ALT"}, bytes.NewBuffer(nil), errWriter{err: errors.New("delete encode fail")}, io.Discard); err == nil {
		t.Fatal("expected secretDeleteCommand encode failure")
	}

	var deleteOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "delete", "--yes", "MISSING_SECRET"}, bytes.NewBuffer(nil), &deleteOut, &deleteOut); err != nil {
		t.Fatalf("secret delete missing: %v", err)
	}
	if !strings.Contains(deleteOut.String(), "missing") {
		t.Fatalf("expected delete missing summary, got %q", deleteOut.String())
	}

	var cancelDeleteOut bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "delete", "API_TOKEN_ALT"}, bytes.NewBufferString("n\n"), &cancelDeleteOut, &cancelDeleteOut); err != nil {
		t.Fatalf("secret delete cancel: %v", err)
	}
	if !strings.Contains(cancelDeleteOut.String(), "missing") {
		t.Fatalf("expected cancelled delete to be reported, got %q", cancelDeleteOut.String())
	}

	if _, _, _, err := ensureProjectBindingExplicit(context.Background(), handle, nonRepo); err == nil {
		t.Fatal("expected explicit binding on non-git path to fail")
	}
	origResolveBinding := resolveBindingViewAppFn
	defer func() { resolveBindingViewAppFn = origResolveBinding }()
	resolveBindingViewAppFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{}, nil, errors.New("binding fail")
	}
	if _, _, _, err := ensureProjectBindingExplicit(context.Background(), handle, secondProjectRoot); err == nil || !strings.Contains(err.Error(), "binding fail") {
		t.Fatalf("expected resolve binding failure, got %v", err)
	}

	resolvePrompt := newSecretPrompt(bytes.NewBufferString("4\n"), io.Discard, io.Discard)
	if _, _, _, err := resolveSecretAddCollision(handle, "API_TOKEN", []byte("value"), "", resolvePrompt); err == nil {
		t.Fatal("expected cancelled collision resolution")
	}
	if _, _, outcome, err := resolveSecretAddCollision(handle, "API_TOKEN", []byte("value"), "replace", resolvePrompt); err != nil || outcome != "updated" {
		t.Fatalf("expected replace collision outcome, got %q err=%v", outcome, err)
	}
	if _, _, outcome, err := resolveSecretAddCollision(handle, "API_TOKEN", []byte("value"), "skip", resolvePrompt); err != nil || outcome != "skipped" {
		t.Fatalf("expected skip collision outcome, got %q err=%v", outcome, err)
	}
	if _, _, _, err := resolveSecretAddCollision(handle, "API_TOKEN", []byte("value"), "bogus", resolvePrompt); err == nil {
		t.Fatal("expected invalid on-conflict mode to error")
	}
	if _, _, outcome, err := resolveSecretAddCollision(handle, "BRAND_NEW", []byte("value"), "", resolvePrompt); err != nil || outcome != "created" {
		t.Fatalf("expected created collision outcome for brand new secret, got %q err=%v", outcome, err)
	}
}

func TestSecretCommandsVaultOpenFailuresAndDefaultLoadFailures(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "")

	origLoad := loadCLIConfigAppFn
	defer func() { loadCLIConfigAppFn = origLoad }()

	commands := []func() error{
		func() error {
			return secretAddCommand(context.Background(), nil, bytes.NewBufferString("KEY\nvalue\nn\n"), io.Discard, io.Discard)
		},
		func() error {
			return secretUpdateCommand(context.Background(), []string{"KEY=value"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
		},
		func() error {
			return secretDeleteCommand(context.Background(), []string{"--yes", "KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
		},
		func() error {
			return secretGetCommand(context.Background(), []string{"KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
		},
		func() error { return secretListCommand(context.Background(), nil, io.Discard) },
		func() error {
			return secretExposeCommand(context.Background(), []string{"KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
		},
		func() error {
			return secretHideCommand(context.Background(), []string{"KEY"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
		},
	}
	for idx, command := range commands {
		if err := command(); err == nil {
			t.Fatalf("expected vault open failure for command %d", idx)
		}
	}

	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}
	gitRoot := t.TempDir()
	if out, err := run("git", "-C", gitRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	loadCLIConfigAppFn = func() (paths.CLIConfig, error) { return paths.CLIConfig{}, errors.New("load fail") }
	if _, _, _, err := ensureProjectBindingExplicit(context.Background(), handle, gitRoot); err == nil || !strings.Contains(err.Error(), "load fail") {
		t.Fatalf("expected load defaults failure, got %v", err)
	}
	loadCLIConfigAppFn = origLoad
	origUpsert := secretUpsertItemFn
	origBind := secretBindItemAliasFn
	origGet := secretGetItemFn
	origDelete := secretDeleteItemFn
	origHide := secretHideItemFn
	origList := secretListItemsFn
	origExposures := secretItemExposuresFn
	defer func() {
		secretUpsertItemFn = origUpsert
		secretBindItemAliasFn = origBind
		secretGetItemFn = origGet
		secretDeleteItemFn = origDelete
		secretHideItemFn = origHide
		secretListItemsFn = origList
		secretItemExposuresFn = origExposures
	}()

	secretGetwdFn = func() (string, error) { return gitRoot, nil }
	secretUpsertItemFn = func(*store.Handle, string, store.ItemKind, []byte, store.ItemMetadata) (store.Item, error) {
		return store.Item{}, errors.New("upsert fail")
	}
	if err := secretAddCommand(context.Background(), []string{"--expose=always", "TOKEN"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "upsert fail") {
		t.Fatalf("expected add upsert failure, got %v", err)
	}
	secretUpsertItemFn = origUpsert

	secretBindItemAliasFn = func(*store.Handle, context.Context, string, string) (string, error) {
		return "", errors.New("bind fail")
	}
	if err := secretAddCommand(context.Background(), []string{"--expose=always", "TOKEN2"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "bind fail") {
		t.Fatalf("expected add bind failure, got %v", err)
	}
	secretBindItemAliasFn = origBind

	if err := Run(context.Background(), []string{"set", "--name", "TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("seed TOKEN for update/delete failures: %v", err)
	}
	secretUpsertItemFn = func(*store.Handle, string, store.ItemKind, []byte, store.ItemMetadata) (store.Item, error) {
		return store.Item{}, errors.New("update fail")
	}
	if err := secretUpdateCommand(context.Background(), []string{"TOKEN"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "update fail") {
		t.Fatalf("expected update upsert failure, got %v", err)
	}
	secretUpsertItemFn = origUpsert

	secretDeleteItemFn = func(*store.Handle, string) error { return errors.New("delete fail") }
	if err := secretDeleteCommand(context.Background(), []string{"--yes", "TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "delete fail") {
		t.Fatalf("expected delete failure branch, got %v", err)
	}
	secretDeleteItemFn = origDelete

	secretGetItemFn = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get fail") }
	if err := secretGetCommand(context.Background(), []string{"TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "get fail") {
		t.Fatalf("expected get failure branch, got %v", err)
	}
	if err := secretExposeCommand(context.Background(), []string{"TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "get fail") {
		t.Fatalf("expected expose get failure branch, got %v", err)
	}
	secretGetItemFn = origGet

	secretHideItemFn = func(*store.Handle, context.Context, string, string) ([]string, error) {
		return nil, errors.New("hide fail")
	}
	if err := secretHideCommand(context.Background(), []string{"TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "hide fail") {
		t.Fatalf("expected hide failure branch, got %v", err)
	}
	secretHideItemFn = origHide

	secretListItemsFn = func(*store.Handle) []store.Item {
		return []store.Item{{Name: "LISTED", Kind: store.ItemKindKV}}
	}
	secretItemExposuresFn = func(*store.Handle, string) []store.ItemExposure {
		return []store.ItemExposure{{ProjectRoot: gitRoot, Reference: "secret_01"}}
	}
	if err := secretListCommand(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("expected populated list to encode, got %v", err)
	}
}
