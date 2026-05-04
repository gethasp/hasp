package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
	"github.com/gethasp/hasp/apps/server/internal/app/cmddispatch"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/app/vaultaccess"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/release"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type marshalFail struct{}

func (marshalFail) MarshalJSON() ([]byte, error) {
	return nil, errors.New("marshal fail")
}

type failAfterWriter struct {
	remaining int
	err       error
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.err == nil {
		w.err = errors.New("write fail")
	}
	if w.remaining <= 0 {
		return 0, w.err
	}
	w.remaining--
	return len(p), nil
}

type fakeTempWriteFile struct {
	writeErr error
	closeErr error
}

func (f fakeTempWriteFile) Write([]byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return 1, nil
}

func (f fakeTempWriteFile) Close() error {
	return f.closeErr
}

func TestCoverage100SmallHelpersAndWrappers(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "")
	if localeSupportsUTF8() {
		t.Fatal("expected localeSupportsUTF8 to be conservative without locale env")
	}

	t.Setenv("COLUMNS", "120")
	if got := defaultTerminalColumns(); got != 120 {
		t.Fatalf("valid COLUMNS = %d, want 120", got)
	}
	t.Setenv("COLUMNS", "nope")
	if got := defaultTerminalColumns(); got != 0 {
		t.Fatalf("invalid COLUMNS = %d, want 0", got)
	}
	t.Setenv("COLUMNS", "-1")
	if got := defaultTerminalColumns(); got != 0 {
		t.Fatalf("negative COLUMNS = %d, want 0", got)
	}
	if got := clipForTerminal("abcdef", 10, 10); got != "abcdef" {
		t.Fatalf("clip with no budget = %q", got)
	}
	t.Setenv("HOME", "")
	if _, err := expandUserPath("~/missing-home"); err == nil {
		t.Fatal("expected expandUserPath home lookup error")
	}

	var nilCtx context.Context
	if globalFlagsFromContext(nilCtx) != (globalFlags{}) {
		t.Fatal("nil context should produce zero global flags")
	}
	if globalFlagsFromContext(context.TODO()) != (globalFlags{}) {
		t.Fatal("context without global flags should produce zero global flags")
	}
	for _, args := range [][]string{
		{"--json=bad", "doctor"},
		{"--yes=bad", "doctor"},
		{"--quiet=bad", "doctor"},
		{"--verbose=bad", "doctor"},
		{"--debug=bad", "doctor"},
		{"--version=bad", "doctor"},
		{"--no-color=bad", "doctor"},
	} {
		if _, _, err := parseGlobalFlags(args); err == nil {
			t.Fatalf("parseGlobalFlags(%v) expected error", args)
		}
	}
	if _, err := parseGlobalBool("--json", "bad", true); err == nil {
		t.Fatal("expected parseGlobalBool invalid-value error")
	}
	if _, _, err := resolveGrant("nonsense", 0); err == nil {
		t.Fatal("expected resolveGrant parse error")
	}
	if _, err := pickGrantWindow(time.Second, 2*time.Second); err == nil {
		t.Fatal("expected conflicting grant window error")
	}

	if got := AppErrorExitCode(newAppError(errCodeUserInput, "bad input")); got != exitUserInput {
		t.Fatalf("AppErrorExitCode wrapper = %d, want %d", got, exitUserInput)
	}
	for _, err := range []error{
		nil,
		store.ErrVaultNotInitialized,
		store.ErrInvalidPassword,
		store.ErrItemNotFound,
		errors.New("missing --name"),
		errors.New("daemon unreachable"),
	} {
		_ = classifyAppError(err)
	}

	var stderr bytes.Buffer
	WriteCLIError(&stderr, errors.New("plain"), false)
	WriteCLIError(nil, errors.New("plain"), false)
	WriteCLIError(&stderr, nil, true)
	if !bytes.Contains(stderr.Bytes(), []byte("plain")) {
		t.Fatalf("expected plain WriteCLIError output, got %q", stderr.String())
	}
	if !ArgsRequestJSON([]string{"secret", "list", "--json"}) {
		t.Fatal("ArgsRequestJSON wrapper did not detect --json")
	}
	if ArgsRequestJSON([]string{"secret", "list"}) {
		t.Fatal("ArgsRequestJSON wrapper returned true without --json")
	}
	for _, doc := range [][]byte{
		[]byte(``),
		[]byte(`{} {}`),
		[]byte(`{} x`),
		[]byte("{}\ntrue"),
	} {
		if err := assertSingleJSONDocument(doc); err == nil {
			t.Fatalf("assertSingleJSONDocument(%q) expected error", doc)
		}
	}

	if err := writeJSONResponse(io.Discard, marshalFail{}); err == nil {
		t.Fatal("expected marshal failure")
	}
	if err := writeJSONResponse(errWriter{err: errors.New("write fail")}, map[string]string{}); err == nil {
		t.Fatal("expected empty-object write failure")
	}
	if err := writeJSONResponse(errWriter{err: errors.New("write fail")}, map[string]string{"a": "b"}); err == nil {
		t.Fatal("expected object write failure")
	}
	if err := writeJSONResponse(&failAfterWriter{remaining: 1}, map[string]string{"a": "b"}); err == nil {
		t.Fatal("expected object body write failure")
	}
	if err := writeJSONResponse(errWriter{err: errors.New("write fail")}, []string{"a"}); err == nil {
		t.Fatal("expected array write failure")
	}
	var jsonOut bytes.Buffer
	if err := writeJSONResponse(&jsonOut, []string{"a"}); err != nil {
		t.Fatalf("writeJSONResponse array: %v", err)
	}
	if !json.Valid(bytes.TrimSpace(jsonOut.Bytes())) {
		t.Fatalf("invalid json response %q", jsonOut.String())
	}

	noteSetupCanonical(nil, "init")
	if got := buildUsageLine("x", nil); got != "usage: hasp x" {
		t.Fatalf("nil usage line = %q", got)
	}
	emptyFS := flag.NewFlagSet("empty", flag.ContinueOnError)
	if got := buildUsageLine("x", emptyFS); got != "usage: hasp x" {
		t.Fatalf("empty usage line = %q", got)
	}
	if usageArgLabel(nil) != "" {
		t.Fatal("nil flag should have empty usage label")
	}
	if got := uniqueSorted(nil); got != nil {
		t.Fatalf("uniqueSorted(nil) = %#v", got)
	}
	if got := Complete([]string{"status", "--"}, CompletionOptions{}); got != nil {
		t.Fatalf("status flag completion = %#v, want nil", got)
	}
	if got := Complete([]string{"status", "x"}, CompletionOptions{}); got != nil {
		t.Fatalf("status subcompletion = %#v, want nil", got)
	}
	emitDeprecationWarning(context.Background(), nil, "unused")
	writeRootHelpCommandSection(&strings.Builder{}, "Hidden", []rootCommandSpec{{name: "hidden", hidden: true}})
	if levenshtein("", "abc") != 3 || levenshtein("abc", "") != 3 {
		t.Fatal("unexpected levenshtein empty-string result")
	}
}

func TestCoverage100RunWithStarterDispatchBranches(t *testing.T) {
	var out bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"--bad"}, bytes.NewReader(nil), &out, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected top-level flag parse error")
	}
	if err := runWithStarter(context.Background(), []string{"--json"}, bytes.NewReader(nil), &out, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("global-only help: %v", err)
	}
	if err := runWithStarter(context.Background(), []string{"--debug", "version"}, bytes.NewReader(nil), &out, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("debug version: %v", err)
	}
	if err := runWithStarter(context.Background(), []string{"--json", "help"}, bytes.NewReader(nil), &out, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("global help: %v", err)
	}
	if err := runWithStarter(context.Background(), []string{"--json", "--help"}, bytes.NewReader(nil), &out, io.Discard, &fakeStarter{}); err != nil {
		t.Fatalf("global --help: %v", err)
	}
}

func TestCoverage100PassphraseBranches(t *testing.T) {
	lockAppSeams(t)

	if got := stdinReaderFn(); got == nil {
		t.Fatal("default stdinReaderFn returned nil")
	}
	if got := openFDFn(0); got == nil {
		t.Fatal("default openFDFn returned nil")
	}

	if pass, err := readPassphrase(false, -1, "env-value", ""); err != nil || pass != "env-value" {
		t.Fatalf("env fallback with default name = %q err=%v", pass, err)
	}

	origStdinReader := stdinReaderFn
	origOpenFD := openFDFn
	defer func() {
		stdinReaderFn = origStdinReader
		openFDFn = origOpenFD
	}()

	stdinReaderFn = func() io.Reader { return errReader{err: errors.New("stdin fail")} }
	if _, err := readPassphrase(true, -1, "", "ENV"); err == nil {
		t.Fatal("expected stdin read error")
	}
	openFDFn = func(uintptr) *os.File { return nil }
	if _, err := readPassphrase(false, 9, "", "ENV"); err == nil {
		t.Fatal("expected nil fd error")
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed-fd")
	if err != nil {
		t.Fatalf("create temp fd: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("close temp fd: %v", err)
	}
	openFDFn = func(uintptr) *os.File { return closed }
	if _, err := readPassphrase(false, 9, "", "ENV"); err == nil {
		t.Fatal("expected closed fd read error")
	}
	stdinReaderFn = func() io.Reader { return strings.NewReader("\n") }
	if _, err := readPassphrase(true, -1, "", "ENV"); err == nil {
		t.Fatal("expected empty stdin passphrase error")
	}
}

func TestCoverage100DocsCompletionAndSetupEdges(t *testing.T) {
	if err := docsCommand(context.Background(), nil, io.Discard, io.Discard); err == nil {
		t.Fatal("expected docs usage error")
	}
	if err := docsMarkdownCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected docs markdown parse error")
	}
	if err := docsMarkdownCommand(context.Background(), []string{"--out", filepath.Join(t.TempDir(), "docs.md"), "extra"}, io.Discard); err == nil {
		t.Fatal("expected docs markdown extra-arg error")
	}
	if err := docsMarkdownCommand(context.Background(), []string{"--out", "~\x00bad"}, io.Discard); err == nil {
		t.Fatal("expected docs markdown expand error")
	}
	origTopics := helpTopicInventory
	helpTopicInventory = append([]helpTopicSpec(nil), helpTopicInventory...)
	helpTopicInventory = append(helpTopicInventory, helpTopicSpec{key: "coverage-no-newline", text: "no trailing newline"})
	defer func() { helpTopicInventory = origTopics }()
	if !strings.Contains(renderDocsMarkdown(), "```") {
		t.Fatal("expected fenced code blocks in docs markdown")
	}

	if _, err := parseBootstrapOptions([]string{"--project-root", "~\x00bad"}, true); err == nil {
		t.Fatal("expected bootstrap project-root expand error")
	}
	if _, _, err := parseSetupOptions([]string{"--repo", "~\x00bad"}); err == nil {
		t.Fatal("expected setup repo expand error")
	}
	if _, _, err := parseSetupOptions([]string{"--import", "~\x00bad"}); err == nil {
		t.Fatal("expected setup import expand error")
	}

	prompt := &setupPrompter{}
	if setupCanRepeatPasswordAfterEOF(prompt) {
		t.Fatal("nil setup prompt file should not be repeatable")
	}
}

func TestCoverage100AuditTailBranches(t *testing.T) {
	lockAppSeams(t)

	origNewAuditLog := newAuditLogFn
	origAuditEvents := auditEventsFn
	origOpenVault := openVaultHandleFn
	defer func() {
		newAuditLogFn = origNewAuditLog
		auditEventsFn = origAuditEvents
		openVaultHandleFn = origOpenVault
	}()

	if err := auditTailCommand(context.Background(), []string{"--bad"}, io.Discard, auditTailOpts{}); err == nil {
		t.Fatal("expected audit tail parse error")
	}
	if err := auditTailCommand(context.Background(), []string{"extra"}, io.Discard, auditTailOpts{}); err == nil {
		t.Fatal("expected audit tail usage error")
	}
	if err := auditTailCommand(context.Background(), []string{"--project-root", "~\x00bad"}, io.Discard, auditTailOpts{}); err == nil {
		t.Fatal("expected audit tail project-root expand error")
	}
	newAuditLogFn = func() (*audit.Log, error) { return &audit.Log{}, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return nil, nil }
	if err := auditTailCommand(context.Background(), []string{"--blocked"}, io.Discard, auditTailOpts{}); err != nil {
		t.Fatalf("audit tail blocked filter: %v", err)
	}

	newAuditLogFn = func() (*audit.Log, error) { return nil, errors.New("audit open fail") }
	if err := auditTailCommand(context.Background(), nil, io.Discard, auditTailOpts{}); err == nil {
		t.Fatal("expected audit log open error")
	}

	newAuditLogFn = origNewAuditLog
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return nil, errors.New("events fail") }
	if err := auditTailCommand(context.Background(), nil, io.Discard, auditTailOpts{}); err == nil {
		t.Fatal("expected audit events error")
	}

	auditEventsFn = func(*audit.Log) ([]audit.Event, error) {
		return []audit.Event{{Sequence: 1, Type: "secret.get", Timestamp: time.Now().UTC()}}, nil
	}
	if err := renderAuditTail([]audit.Event{{Details: map[string]any{"bad": func() {}}}}, true, io.Discard); err == nil {
		t.Fatal("expected audit tail marshal error")
	}
	if err := renderAuditTail([]audit.Event{{Type: "x"}}, true, errWriter{err: errors.New("write fail")}); err == nil {
		t.Fatal("expected audit tail write error")
	}

	newAuditLogFn = func() (*audit.Log, error) { return &audit.Log{}, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) {
		return []audit.Event{{Sequence: 1, Type: "x", Timestamp: time.Now().UTC()}}, nil
	}
	if err := auditTailCommand(context.Background(), []string{"--json"}, errWriter{err: errors.New("write fail")}, auditTailOpts{}); err == nil {
		t.Fatal("expected audit tail initial render error")
	}

	t.Setenv("HASP_HOME", t.TempDir())
	vaultStore, err := store.New(store.NewDefaultKeyring())
	if err != nil {
		t.Fatalf("store new: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("store init: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return handle, nil }
	if err := auditTailCommand(context.Background(), nil, io.Discard, auditTailOpts{}); err != nil {
		t.Fatalf("audit tail with vault key: %v", err)
	}
	setAuditHMACKey([]byte("audit-key"))
	if err := auditTailCommand(context.Background(), nil, io.Discard, auditTailOpts{}); err != nil {
		t.Fatalf("audit tail with cached key: %v", err)
	}
	clearAuditHMACKey()

	calls := 0
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) {
		calls++
		if calls == 1 {
			return []audit.Event{{Sequence: 1, Type: "initial", Timestamp: time.Now().UTC()}}, nil
		}
		return nil, errors.New("follow fail")
	}
	if err := auditTailCommand(context.Background(), []string{"--follow"}, io.Discard, auditTailOpts{PollInterval: time.Millisecond}); err == nil {
		t.Fatal("expected audit tail follow error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) {
		calls++
		switch calls {
		case 1:
			return []audit.Event{{Sequence: 1, Type: "initial", Timestamp: time.Now().UTC()}}, nil
		case 2:
			return []audit.Event{{Sequence: 1, Type: "initial", Timestamp: time.Now().UTC()}}, nil
		case 3:
			return []audit.Event{{Sequence: 1, Type: "initial", Timestamp: time.Now().UTC()}, {Sequence: 2, Type: "drop", Timestamp: time.Now().UTC(), Details: map[string]any{"reference": "other"}}}, nil
		default:
			cancel()
			return []audit.Event{{Sequence: 1, Type: "initial", Timestamp: time.Now().UTC()}, {Sequence: 3, Type: "keep", Timestamp: time.Now().UTC(), Details: map[string]any{"reference": "keep"}}}, nil
		}
	}
	if err := auditTailCommand(ctx, []string{"--follow", "--secret", "keep"}, io.Discard, auditTailOpts{PollInterval: time.Millisecond}); err != nil {
		t.Fatalf("audit tail follow filters: %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	calls = 0
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) {
		calls++
		if calls == 1 {
			return []audit.Event{{Sequence: 1, Type: "initial", Timestamp: time.Now().UTC()}}, nil
		}
		cancel()
		return []audit.Event{{Sequence: 1, Type: "initial", Timestamp: time.Now().UTC()}, {Sequence: 2, Type: "delta", Timestamp: time.Now().UTC()}}, nil
	}
	if err := auditTailCommand(ctx, []string{"--follow"}, io.Discard, auditTailOpts{PollInterval: time.Millisecond}); err != nil {
		t.Fatalf("audit tail follow render delta: %v", err)
	}
}

func TestCoverage100DefaultDependencyAdapters(t *testing.T) {
	lockAppSeams(t)

	origAppResolve := appResolvePathsFn
	origAppWrite := appWriteFileFn
	origAppRead := appReadFileFn
	origAppMkdir := appMkdirAllFn
	origAppCurrentShell := appCurrentShellFn
	origAppUserHome := appUserHomeDirFn
	origAppInstall := appInstallLauncherFn
	origAgentAtomic := agentAtomicWriteFn
	origAgentOpen := agentOpenSessionFn
	origNewStarter := newRuntimeStarterFn
	origSecretIsChar := secretIsCharDeviceFn
	origSecretRevealTTY := secretRevealIsTTYFn
	origSecretGetwd := secretGetwdFn
	origCanonical := appCanonicalProjectRootFn
	origResolveBinding := resolveBindingViewAppFn
	defer func() {
		appResolvePathsFn = origAppResolve
		appWriteFileFn = origAppWrite
		appReadFileFn = origAppRead
		appMkdirAllFn = origAppMkdir
		appCurrentShellFn = origAppCurrentShell
		appUserHomeDirFn = origAppUserHome
		appInstallLauncherFn = origAppInstall
		agentAtomicWriteFn = origAgentAtomic
		agentOpenSessionFn = origAgentOpen
		newRuntimeStarterFn = origNewStarter
		secretIsCharDeviceFn = origSecretIsChar
		secretRevealIsTTYFn = origSecretRevealTTY
		secretGetwdFn = origSecretGetwd
		appCanonicalProjectRootFn = origCanonical
		resolveBindingViewAppFn = origResolveBinding
	}()

	home := t.TempDir()
	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{HomeDir: home}, nil }
	appWriteFileFn = func(path string, data []byte, perm os.FileMode) error { return nil }
	appReadFileFn = func(path string) ([]byte, error) { return []byte("data"), nil }
	appMkdirAllFn = func(path string, perm os.FileMode) error { return nil }
	appCurrentShellFn = func() string { return "/bin/zsh" }
	appUserHomeDirFn = func() (string, error) { return home, nil }
	appInstallLauncherFn = func(name string) (string, error) { return filepath.Join(home, name), nil }
	newRuntimeStarterFn = func() (*runtimeStarter, error) { return nil, errors.New("starter fail") }

	appDeps := defaultAppDeps()
	if got, err := appDeps.AppResolvePaths(); err != nil || got != home {
		t.Fatalf("AppResolvePaths = %q err=%v", got, err)
	}
	appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{}, errors.New("resolve fail") }
	if _, err := appDeps.AppResolvePaths(); err == nil {
		t.Fatal("expected AppResolvePaths error")
	}
	if err := appDeps.AppWriteFile("x", []byte("data"), 0o600); err != nil {
		t.Fatalf("AppWriteFile: %v", err)
	}
	if got, err := appDeps.AppReadFile("x"); err != nil || string(got) != "data" {
		t.Fatalf("AppReadFile = %q err=%v", string(got), err)
	}
	if err := appDeps.AppMkdirAll("x", 0o700); err != nil {
		t.Fatalf("AppMkdirAll: %v", err)
	}
	if appDeps.AppCurrentShell() != "/bin/zsh" {
		t.Fatal("AppCurrentShell did not use seam")
	}
	if got, err := appDeps.AppUserHomeDir(); err != nil || got != home {
		t.Fatalf("AppUserHomeDir = %q err=%v", got, err)
	}
	if got, err := appDeps.AppInstallLauncher("tool"); err != nil || filepath.Base(got) != "tool" {
		t.Fatalf("AppInstallLauncher = %q err=%v", got, err)
	}
	if _, err := appDeps.AppNewStarter(); err == nil {
		t.Fatal("expected AppNewStarter seam error")
	}

	agentAtomicWriteFn = func(path string, existing, updated []byte) (string, bool, error) {
		return path + ".bak", true, nil
	}
	agentOpenSessionFn = func(context.Context, *runtime.Client, string, store.AgentConsumer) (runtime.OpenSessionResponse, error) {
		return runtime.OpenSessionResponse{SessionToken: "tok"}, nil
	}
	agentDeps := defaultAgentDeps()
	if backup, changed, err := agentDeps.AgentAtomicWrite("cfg", nil, nil); err != nil || !changed || backup != "cfg.bak" {
		t.Fatalf("AgentAtomicWrite = %q %t err=%v", backup, changed, err)
	}
	if reply, err := agentDeps.AgentOpenSession(context.Background(), nil, "host", store.AgentConsumer{}); err != nil || reply.SessionToken != "tok" {
		t.Fatalf("AgentOpenSession = %+v err=%v", reply, err)
	}

	runtimeDeps := defaultRuntimeDeps()
	if got := runtimeDeps.ConnectIfRunning(context.Background(), nil); got != nil {
		t.Fatalf("ConnectIfRunning(nil) = %+v", got)
	}
	if got := runtimeDeps.ConnectIfRunning(context.Background(), &fakeStarter{err: errors.New("dial fail")}); got != nil {
		t.Fatalf("ConnectIfRunning(failing starter) = %+v", got)
	}
	if _, err := runtimeDeps.NewStarter(); err == nil {
		t.Fatal("expected runtime NewStarter seam error")
	}

	secretIsCharDeviceFn = func(*os.File) bool { return true }
	secretRevealIsTTYFn = func(io.Writer) bool { return true }
	secretGetwdFn = func() (string, error) { return home, nil }
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) { return home, nil }
	resolveBindingViewAppFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{ID: "binding"}, nil, nil
	}
	secretDeps := defaultSecretDeps()
	if !secretDeps.IsCharDevice(nil) || !secretDeps.RevealIsTTY(io.Discard) {
		t.Fatal("secret tty deps did not use seams")
	}
	if got, err := secretDeps.Getwd(); err != nil || got != home {
		t.Fatalf("secret Getwd = %q err=%v", got, err)
	}
	if got, err := secretDeps.CanonicalProjectRoot(context.Background(), "."); err != nil || got != home {
		t.Fatalf("CanonicalProjectRoot = %q err=%v", got, err)
	}
	if binding, _, err := secretDeps.ResolveBindingView(nil, context.Background(), "."); err != nil || binding.ID != "binding" {
		t.Fatalf("ResolveBindingView = %+v err=%v", binding, err)
	}
	if secretDeps.PromptIsInteractive(nil) {
		t.Fatal("nil prompt should not be interactive")
	}
	prompt := secretDeps.NewSecretPrompt(strings.NewReader("3\n"), io.Discard, io.Discard)
	if choice, _, err := prompt.Collision("API_TOKEN"); err != nil || choice != "skip" {
		t.Fatalf("prompt collision = %q err=%v", choice, err)
	}

	sessionDeps := defaultSessionDeps()
	if _, err := sessionDeps.NewStarter(); err == nil {
		t.Fatal("expected session NewStarter seam error")
	}
	ctx := contextWithGlobalFlags(context.Background(), globalFlags{json: true})
	if !sessionDeps.GlobalJSON(ctx) {
		t.Fatal("session GlobalJSON did not read context")
	}
	_ = sessionDeps.DefaultConfirmPlaintextGrantDeps()

	vaultDeps := defaultVaultDeps()
	if _, err := vaultDeps.NewStarter(); err == nil {
		t.Fatal("expected vault NewStarter seam error")
	}
	if !vaultDeps.GlobalJSON(ctx) {
		t.Fatal("vault GlobalJSON did not read context")
	}

	t.Setenv("HASP_HOME", t.TempDir())
	vaultStore, err := store.New(store.NewDefaultKeyring())
	if err != nil {
		t.Fatalf("store new: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("store init: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	grantDeps := defaultVaultGrantOpsDeps()
	if _, err := grantDeps.DisableConvenienceUnlock(handle, context.Background()); err != nil {
		t.Fatalf("DisableConvenienceUnlock: %v", err)
	}
}

func TestCoverage100RegisteredInitSeams(t *testing.T) {
	lockAppSeams(t)

	origNewAudit := newAuditLogFn
	origEvents := auditEventsFn
	origOpenVault := openVaultHandleFn
	origCanonical := appCanonicalProjectRootFn
	origResolveBinding := resolveBindingViewAppFn
	defer func() {
		newAuditLogFn = origNewAudit
		auditEventsFn = origEvents
		openVaultHandleFn = origOpenVault
		appCanonicalProjectRootFn = origCanonical
		resolveBindingViewAppFn = origResolveBinding
	}()

	newAuditLogFn = func() (*audit.Log, error) { return &audit.Log{}, nil }
	auditEventsFn = func(*audit.Log) ([]audit.Event, error) { return []audit.Event{{Sequence: 1}}, nil }
	if log, err := auditlog.NewLogFn(); err != nil || log == nil {
		t.Fatalf("auditlog.NewLogFn = %+v err=%v", log, err)
	}
	if events, err := auditlog.EventsFn(&audit.Log{}); err != nil || len(events) != 1 {
		t.Fatalf("auditlog.EventsFn = %+v err=%v", events, err)
	}
	if _, err := auditlog.CurrentUserFn(); err != nil {
		t.Fatalf("auditlog.CurrentUserFn: %v", err)
	}

	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, errors.New("open vault fail") }
	if _, err := vaultaccess.OpenVaultFn(context.Background()); err == nil {
		t.Fatal("expected vaultaccess open error")
	}
	appCanonicalProjectRootFn = func(context.Context, string) (string, error) { return "root", nil }
	if got, err := vaultaccess.CanonicalProjectRootFn(context.Background(), "."); err != nil || got != "root" {
		t.Fatalf("vaultaccess canonical = %q err=%v", got, err)
	}
	resolveBindingViewAppFn = func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
		return store.Binding{ID: "binding"}, nil, nil
	}
	if binding, _, err := vaultaccess.ResolveBindingViewFn(nil, context.Background(), "."); err != nil || binding.ID != "binding" {
		t.Fatalf("vaultaccess binding = %+v err=%v", binding, err)
	}

	ctx := contextWithGlobalFlags(context.Background(), globalFlags{json: true, yes: true})
	if !cmddispatch.JSONFlagFn(ctx) || !cmddispatch.YesFlagFn(ctx) {
		t.Fatal("cmddispatch global flag closures did not read context")
	}
}

func TestCoverage100DoctorBranches(t *testing.T) {
	lockAppSeams(t)

	report := doctorReport{}
	t.Setenv("HASP_HOME", "")
	applyDoctorFixes(context.Background(), &report, nil)
	if len(report.FixesFailed) == 0 {
		t.Fatal("expected HASP_HOME unset fix failure")
	}

	missingHome := filepath.Join(t.TempDir(), "missing")
	report = doctorReport{}
	t.Setenv("HASP_HOME", missingHome)
	applyDoctorFixes(context.Background(), &report, nil)
	if len(report.FixesFailed) < 2 {
		t.Fatalf("expected chmod and stale socket failures, got %+v", report.FixesFailed)
	}

	origStatus := doctorRuntimeStatusFn
	defer func() { doctorRuntimeStatusFn = origStatus }()
	report = doctorReport{}
	doctorRuntimeStatusFn = func(context.Context, starter) (runtime.StatusResponse, bool) {
		return runtime.StatusResponse{AuditDegraded: true}, true
	}
	applyDoctorFixes(context.Background(), &report, &fakeStarter{})
	if !report.DaemonRunning || !report.AuditDegraded {
		t.Fatalf("expected daemon status refresh, got %+v", report)
	}

	socketPath := shortSocketPath(t, "live.sock")
	socketDir := filepath.Dir(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	defer listener.Close()
	if removed, err := removeStaleSocketsIn(socketDir); err != nil || removed != 0 {
		t.Fatalf("removeStaleSocketsIn socket = %d err=%v", removed, err)
	}
	if _, err := removeStaleSocketsIn(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected removeStaleSocketsIn read dir error")
	}

	if _, ok := doctorDaemonPing(context.Background(), &fakeStarter{err: errors.New("dial fail")}); ok {
		t.Fatal("failing starter should not ping")
	}
	pingFailStarter := serveAppRuntimeStarter(t, appRuntimeService{pingErr: errors.New("ping fail")})
	if _, ok := doctorDaemonPing(context.Background(), pingFailStarter); ok {
		t.Fatal("ping error should report not ok")
	}

	var out bytes.Buffer
	if err := renderDoctorHumanWithColor(&out, doctorReport{VersionMismatch: true, versionMismatchDetail: "mismatch"}, ui.ColorOptions{}); err != nil {
		t.Fatalf("renderDoctorHumanWithColor: %v", err)
	}
	if !strings.Contains(out.String(), "version_mismatch") {
		t.Fatalf("expected version mismatch row, got %q", out.String())
	}
	if err := doctorCommand(context.Background(), []string{"--project-root", "~\x00bad"}, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected doctor project-root expand error")
	}
}

func TestCoverage100SecretPromptAndPlaintextBranches(t *testing.T) {
	lockAppSeams(t)

	origStderr := os.Stderr
	_, closedStderr, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	if err := closedStderr.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	os.Stderr = closedStderr
	if defaultStderrIsTerminal() {
		t.Fatal("closed stderr should not be terminal")
	}
	os.Stderr = origStderr

	if ok, err := defaultPlaintextTTYConfirmWithDeps(io.Discard, nil, "prompt", func() bool { return true }); err != nil || ok {
		t.Fatalf("nil stdin confirm = %t err=%v", ok, err)
	}
	if _, err := defaultPlaintextTTYConfirmWithDeps(errWriter{err: errors.New("write fail")}, strings.NewReader("y\n"), "prompt", func() bool { return true }); err == nil {
		t.Fatal("expected prompt write error")
	}
	if _, err := defaultPlaintextTTYConfirmWithDeps(io.Discard, errReader{err: errors.New("read fail")}, "prompt", func() bool { return true }); err == nil {
		t.Fatal("expected prompt read error")
	}
	if ok, err := defaultPlaintextTTYConfirmWithDeps(io.Discard, strings.NewReader("yes\n"), "prompt", func() bool { return true }); err != nil || !ok {
		t.Fatalf("yes confirm = %t err=%v", ok, err)
	}

	if secretPromptIsInteractive(nil) {
		t.Fatal("nil secret prompt should not be interactive")
	}
	if expose, err := resolveSecretAddExpose(context.Background(), false, false, "ask", nil); err != nil || expose {
		t.Fatalf("not-in-repo expose = %t err=%v", expose, err)
	}
	if expose, err := resolveSecretAddExpose(context.Background(), true, true, "always", nil); err != nil || expose {
		t.Fatalf("vault-only expose = %t err=%v", expose, err)
	}
	if expose, err := resolveSecretAddExpose(context.Background(), true, false, "always", nil); err != nil || !expose {
		t.Fatalf("always expose = %t err=%v", expose, err)
	}
	if expose, err := resolveSecretAddExpose(context.Background(), true, false, "never", nil); err != nil || expose {
		t.Fatalf("never expose = %t err=%v", expose, err)
	}
	yesCtx := contextWithGlobalFlags(context.Background(), globalFlags{yes: true})
	if expose, err := resolveSecretAddExpose(yesCtx, true, false, "ask", nil); err != nil || !expose {
		t.Fatalf("yes ask expose = %t err=%v", expose, err)
	}
	if _, err := resolveSecretAddExpose(context.Background(), true, false, "ask", nil); err == nil {
		t.Fatal("expected non-interactive ask error")
	}
	if _, err := resolveSecretAddExpose(context.Background(), true, false, "bad", nil); err == nil {
		t.Fatal("expected bad expose mode error")
	}

	origSecretIsChar := secretIsCharDeviceFn
	defer func() { secretIsCharDeviceFn = origSecretIsChar }()
	secretIsCharDeviceFn = func(*os.File) bool { return true }
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe prompt: %v", err)
	}
	if _, err := w.WriteString("y\n"); err != nil {
		t.Fatalf("write prompt: %v", err)
	}
	_ = w.Close()
	prompt := newSecretPrompt(r, io.Discard, io.Discard)
	if expose, err := resolveSecretAddExpose(context.Background(), true, false, "ask", prompt); err != nil || !expose {
		t.Fatalf("interactive ask expose = %t err=%v", expose, err)
	}
	_ = r.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe prompt error: %v", err)
	}
	_ = errW.Close()
	_ = errR.Close()
	if _, err := resolveSecretAddExpose(context.Background(), true, false, "ask", newSecretPrompt(errR, io.Discard, io.Discard)); err == nil {
		t.Fatal("expected interactive confirm read error")
	}

	if _, err := secretAddInputs([]string{"API_TOKEN=value"}, newSecretPrompt(strings.NewReader(""), io.Discard, io.Discard)); err == nil {
		t.Fatal("expected argv value rejection")
	}
	if inputs, err := secretAddInputs([]string{"API_TOKEN"}, newSecretPrompt(strings.NewReader("value\n"), io.Discard, io.Discard)); err != nil || len(inputs) != 1 {
		t.Fatalf("secretAddInputs args = %+v err=%v", inputs, err)
	}

	vaultStore, err := store.New(store.NewDefaultKeyring())
	if err != nil {
		t.Fatalf("store new: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("store init: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	if _, err := handle.UpsertItem("API_TOKEN", store.ItemKindKV, []byte("value"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect daemon: %v", err)
	}
	defer client.Close()
	session, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "coverage",
		TTLSeconds:   int(time.Minute.Seconds()),
		AgentSafe:    true,
		ConsumerName: "coverage-agent",
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	t.Setenv(envSessionToken, session.SessionToken)
	err = enforceSecretPlaintextPolicyInteractive(context.Background(), handle, "API_TOKEN", store.PlaintextReveal, strings.NewReader(""), io.Discard, secretPlaintextDeps{})
	if err == nil {
		t.Fatal("expected plaintext policy error with nil confirm")
	}
	err = enforceSecretPlaintextPolicyInteractive(context.Background(), handle, "API_TOKEN", store.PlaintextReveal, strings.NewReader(""), io.Discard, secretPlaintextDeps{
		Confirm: func(io.Writer, io.Reader, string) (bool, error) { return true, nil },
	})
	if err != nil {
		t.Fatalf("expected confirmed plaintext grant to pass, got %v", err)
	}
}

func TestCoverage100CommandAndArgumentErrors(t *testing.T) {
	lockAppSeams(t)

	if err := runWithStarter(context.Background(), []string{"proof", "--bad"}, bytes.NewReader(nil), io.Discard, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected proof handler parse error")
	}
	restoreKeys := release.SetPinnedKeysForTest(strings.Repeat("00", 32))
	if err := runWithStarter(context.Background(), []string{"upgrade"}, bytes.NewReader(nil), io.Discard, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected upgrade handler missing-version error")
	}
	restoreKeys()
	if err := runWithStarter(context.Background(), []string{"__complete"}, bytes.NewReader(nil), errWriter{err: errors.New("write fail")}, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected __complete write error")
	}

	if err := proofCommand(context.Background(), []string{"--secret", "API", "extra"}, io.Discard, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected proof extra-arg usage")
	}
	if err := proofCommand(context.Background(), []string{"--secret", "API", "--project-root", "~\x00bad"}, io.Discard, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected proof project-root expand error")
	}

	if err := projectAdoptCommand(context.Background(), []string{"--under", "~\x00bad"}, io.Discard); err == nil {
		t.Fatal("expected project adopt expand error")
	}
	if err := projectBindCommand(context.Background(), []string{"--project-root", "~\x00bad"}, io.Discard); err == nil {
		t.Fatal("expected project bind expand error")
	}
	origCanonical := projectCanonicalRootFn
	defer func() { projectCanonicalRootFn = origCanonical }()
	projectCanonicalRootFn = func(context.Context, string) (string, error) { return "", errors.New("canonical fail") }
	if err := projectBindCommand(context.Background(), []string{"--project-root", t.TempDir(), "--allow-non-git"}, io.Discard); err == nil {
		t.Fatal("expected project bind canonical error")
	}
	projectCanonicalRootFn = func(context.Context, string) (string, error) { return "root", nil }
	if err := projectBindCommand(context.Background(), []string{"--project-root", "\x00", "--allow-non-git"}, io.Discard); err == nil {
		t.Fatal("expected project bind stat error")
	}
	projectCanonicalRootFn = origCanonical

	if err := importCommandWithInput(context.Background(), []string{"--project-root", "~\x00bad", "-"}, strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("expected import project-root expand error")
	}
	if err := setCommand(context.Background(), []string{"--name", "API", "--from-file", "~\x00bad"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected set from-file expand error")
	}
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewReader(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init for set command branches: %v", err)
	}
	if err := setCommand(context.Background(), []string{"--name", "API", "--value-stdin"}, errReader{err: errors.New("stdin fail")}, io.Discard, io.Discard); err == nil {
		t.Fatal("expected set value-stdin read error")
	}
	valueFile := filepath.Join(t.TempDir(), "value.txt")
	if err := os.WriteFile(valueFile, []byte("value"), 0o600); err != nil {
		t.Fatalf("write value file: %v", err)
	}
	if err := setCommand(context.Background(), []string{"--name", "API", "--value", "inline", "--from-file", valueFile}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected set resolve value conflict")
	}

	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--project-root", projectRoot, "--from-stdin", "--expose=always", "API_TOKEN"}, strings.NewReader("secret-value\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add for exec branches: %v", err)
	}
	starter := newDaemonTestStarter(t)
	origTTY := stdoutIsTTYFn
	stdoutIsTTYFn = func(io.Writer) bool { return true }
	deps := defaultExecDeps()
	deps.RunnerExecute = func(ctx context.Context, input runner.Input) (runner.Result, error) {
		if !input.TTY {
			t.Fatalf("expected executeCommandWithDeps to request TTY")
		}
		return runner.Result{ExitCode: 0}, nil
	}
	if err := executeCommandWithDeps(context.Background(), []string{"--project-root", projectRoot, "--env", "API=@API_TOKEN", "--grant-project", "once", "--grant-secret", "once", "--", "true"}, io.Discard, io.Discard, false, starter, deps); err != nil {
		t.Fatalf("execute tty branch: %v", err)
	}
	stdoutIsTTYFn = origTTY

	writeEnvArgs := func(output string, extra ...string) []string {
		args := []string{"--project-root", projectRoot, "--output", output, "--env", "API=@API_TOKEN", "--grant-project", "once", "--grant-secret", "once"}
		args = append(args, extra...)
		return args
	}
	noConvenienceOut := filepath.Join(t.TempDir(), "no-convenience.env")
	if err := writeEnvCommandWithDeps(context.Background(), writeEnvArgs(noConvenienceOut), io.Discard, io.Discard, starter, deps); err == nil {
		t.Fatal("expected write-env convenience approval error")
	}
	dirOutput := t.TempDir()
	if err := writeEnvCommandWithDeps(context.Background(), writeEnvArgs(dirOutput, "--append", "--grant-convenience", "once"), io.Discard, io.Discard, starter, deps); err == nil {
		t.Fatal("expected write-env append read directory error")
	}
	malformed := filepath.Join(t.TempDir(), "malformed.env")
	if err := os.WriteFile(malformed, []byte(writeEnvBlockBegin+"\nOLD=1\n"), 0o600); err != nil {
		t.Fatalf("write malformed env: %v", err)
	}
	if err := writeEnvCommandWithDeps(context.Background(), writeEnvArgs(malformed, "--append", "--grant-convenience", "once"), io.Discard, io.Discard, starter, deps); err != nil {
		t.Fatalf("write-env append malformed block: %v", err)
	}

	origOpenTemp := openWriteEnvTempFileFn
	origRemoveTemp := removeWriteEnvTempFileFn
	origRename := renameWriteEnvFileFn
	defer func() {
		openWriteEnvTempFileFn = origOpenTemp
		removeWriteEnvTempFileFn = origRemoveTemp
		renameWriteEnvFileFn = origRename
	}()
	openWriteEnvTempFileFn = func(string, int, os.FileMode) (writeEnvTempFile, error) {
		return nil, errors.New("open temp fail")
	}
	openFailOut := filepath.Join(t.TempDir(), "open-fail.env")
	if err := os.WriteFile(openFailOut, []byte("EXISTING=1\n"), 0o600); err != nil {
		t.Fatalf("write open fail env: %v", err)
	}
	if err := writeEnvCommandWithDeps(context.Background(), writeEnvArgs(openFailOut, "--append", "--grant-convenience", "once"), io.Discard, io.Discard, starter, deps); err == nil {
		t.Fatal("expected write-env temp open error")
	}
	openWriteEnvTempFileFn = func(string, int, os.FileMode) (writeEnvTempFile, error) {
		return fakeTempWriteFile{writeErr: errors.New("write temp fail")}, nil
	}
	if err := writeEnvCommandWithDeps(context.Background(), writeEnvArgs(openFailOut, "--append", "--grant-convenience", "once"), io.Discard, io.Discard, starter, deps); err == nil {
		t.Fatal("expected write-env temp write error")
	}
	openWriteEnvTempFileFn = func(string, int, os.FileMode) (writeEnvTempFile, error) {
		return fakeTempWriteFile{closeErr: errors.New("close temp fail")}, nil
	}
	if err := writeEnvCommandWithDeps(context.Background(), writeEnvArgs(openFailOut, "--append", "--grant-convenience", "once"), io.Discard, io.Discard, starter, deps); err == nil {
		t.Fatal("expected write-env temp close error")
	}
	removedTemp := false
	openWriteEnvTempFileFn = func(string, int, os.FileMode) (writeEnvTempFile, error) {
		return fakeTempWriteFile{}, nil
	}
	removeWriteEnvTempFileFn = func(string) error {
		removedTemp = true
		return nil
	}
	renameWriteEnvFileFn = func(string, string) error { return errors.New("rename fail") }
	if err := writeEnvCommandWithDeps(context.Background(), writeEnvArgs(openFailOut, "--append", "--grant-convenience", "once"), io.Discard, io.Discard, starter, deps); err == nil {
		t.Fatal("expected write-env rename error")
	}
	if !removedTemp {
		t.Fatal("expected failed append to remove temp file")
	}

	if err := captureCommand(context.Background(), []string{"--name", "API", "--grant-project", "bad"}, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected capture project grant parse error")
	}
	if err := captureCommand(context.Background(), []string{"--name", "API", "--grant-secret", "bad"}, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected capture secret grant parse error")
	}
	if err := captureCommand(context.Background(), []string{"--name", "API", "--grant-project", "1s", "--grant-secret", "2s"}, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected capture grant conflict")
	}
	if err := captureCommand(context.Background(), []string{"--name", "API", "--grant-project", "window"}, io.Discard, &fakeStarter{}); err == nil {
		t.Fatal("expected capture grant window validation error")
	}
	if err := auditCommandWithArgs(context.Background(), []string{"--project-root", "~\x00bad"}, io.Discard); err == nil {
		t.Fatal("expected audit project-root expand error")
	}
}

func TestCoverage100ExplainSetupAndSessionBranches(t *testing.T) {
	payload := explainPayload{
		Command:          "write-env",
		ProjectRoot:      "/repo",
		ProjectScope:     "once",
		SecretScope:      "session",
		ConvenienceScope: "window",
		GrantWindow:      time.Minute,
		RedactorActive:   false,
		EnvRefs:          map[string]string{"A": "@api"},
		FileRefs:         map[string]string{"F": "@file"},
		OutputPath:       "/tmp/env",
		ChildCommand:     []string{"true"},
		DryRun:           true,
	}
	var out bytes.Buffer
	if err := writeExplainPayload(&out, payload, "text"); err != nil {
		t.Fatalf("writeExplainPayload text: %v", err)
	}
	if !strings.Contains(out.String(), "convenience_grant") || !strings.Contains(out.String(), "file refs") {
		t.Fatalf("expected full explain text, got %q", out.String())
	}
	if err := writeExplainPayload(errWriter{err: errors.New("write fail")}, payload, "json"); err == nil {
		t.Fatal("expected explain json write error")
	}
	if explainBool(false, "on", "off") != "off" {
		t.Fatal("explainBool false branch failed")
	}

	origSessionUser := sessionCurrentUserFn
	defer func() { sessionCurrentUserFn = origSessionUser }()
	sessionCurrentUserFn = func() (*user.User, error) { return nil, errors.New("user fail") }
	if _, err := defaultSessionLocalDeps().LocalUser(); err == nil {
		t.Fatal("expected LocalUser error")
	}
	sessionCurrentUserFn = func() (*user.User, error) { return &user.User{Uid: "501"}, nil }
	if got, err := defaultSessionLocalDeps().LocalUser(); err != nil || got != "501" {
		t.Fatalf("LocalUser uid fallback = %q err=%v", got, err)
	}
	t.Setenv("HASP_HOME", t.TempDir())
	s, err := store.New(nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := s.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	h, err := s.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	home := os.Getenv("HASP_HOME")
	if err := os.RemoveAll(home); err != nil {
		t.Fatalf("remove home: %v", err)
	}
	if err := os.WriteFile(home, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatalf("poison home path: %v", err)
	}
	if _, err := defaultSessionLocalDeps().UseMutationGrant(h, "binding", "tok", "API_TOKEN", store.SecretMutationExpose, time.Second); err == nil {
		t.Fatal("expected mutation grant project lease error")
	}
	sessionOut := bytes.Buffer{}
	err = renderSessionListWithColor(&sessionOut, []runtime.SessionView{{ID: "s", ExpiresAt: time.Now().Add(time.Minute)}}, ui.ColorOptions{Verbose: true})
	if err != nil {
		t.Fatalf("renderSessionListWithColor verbose: %v", err)
	}

	regular, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatalf("create regular: %v", err)
	}
	defer regular.Close()
	prompt := &setupPrompter{file: regular}
	if setupCanRepeatPasswordAfterEOF(prompt) {
		t.Fatal("regular file should not allow EOF repeat")
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatalf("create closed: %v", err)
	}
	_ = closed.Close()
	if setupCanRepeatPasswordAfterEOF(&setupPrompter{file: closed}) {
		t.Fatal("closed file should not allow EOF repeat")
	}
	devNull, err := os.OpenFile("/dev/null", os.O_RDONLY, 0)
	if err == nil {
		defer devNull.Close()
		_ = setupCanRepeatPasswordAfterEOF(&setupPrompter{file: devNull})
	}
	if _, _, err := setupEnsureHandle(context.Background(), nil, "weak", false, false); err == nil {
		t.Fatal("expected setupEnsureHandle weak password error")
	}
	weakPrompt := newSetupPrompter(strings.NewReader("weak\nweak\n"), &failAfterWriter{remaining: 4})
	if _, _, err := setupResolvePassword(weakPrompt, setupOptions{}, t.TempDir()); err == nil {
		t.Fatal("expected setupResolvePassword weak-password write error")
	}
	if err := setupWriteStage(&failAfterWriter{remaining: 3}, "Title", "1. first", "second"); err == nil {
		t.Fatal("expected setupWriteStage separator write error")
	}
}

func TestCoverage100ExecErrorBranches(t *testing.T) {
	lockAppSeams(t)

	deps := defaultExecDeps()
	if _, err := deps.GitLsFiles(context.Background(), t.TempDir()); err == nil {
		t.Fatal("expected git ls-files error outside git repo")
	}

	if err := executeCommandWithDeps(context.Background(), []string{"--project-root", "~\x00bad", "--", "true"}, io.Discard, io.Discard, false, &fakeStarter{}, deps); err == nil {
		t.Fatal("expected execute project-root expand error")
	}
	if err := executeCommandWithDeps(context.Background(), []string{"--grant-project", "bad", "--", "true"}, io.Discard, io.Discard, false, &fakeStarter{}, deps); err == nil {
		t.Fatal("expected execute project grant error")
	}
	if err := executeCommandWithDeps(context.Background(), []string{"--grant-secret", "bad", "--", "true"}, io.Discard, io.Discard, false, &fakeStarter{}, deps); err == nil {
		t.Fatal("expected execute secret grant error")
	}
	if err := executeCommandWithDeps(context.Background(), []string{"--grant-project", "1s", "--grant-secret", "2s", "--", "true"}, io.Discard, io.Discard, false, &fakeStarter{}, deps); err == nil {
		t.Fatal("expected execute grant conflict")
	}
	if err := executeCommandWithDeps(context.Background(), []string{"--explain", "--explain-format", "bad", "--", "true"}, io.Discard, io.Discard, false, &fakeStarter{}, deps); err == nil {
		t.Fatal("expected execute explain format error")
	}

	base := []string{"--output", filepath.Join(t.TempDir(), "env"), "--env", "A=@api"}
	if err := writeEnvCommandWithDeps(context.Background(), append([]string{"--project-root", "~\x00bad"}, base...), io.Discard, io.Discard, &fakeStarter{}, deps); err == nil {
		t.Fatal("expected write-env project-root expand error")
	}
	if err := writeEnvCommandWithDeps(context.Background(), []string{"--output", "~\x00bad", "--env", "A=@api"}, io.Discard, io.Discard, &fakeStarter{}, deps); err == nil {
		t.Fatal("expected write-env output expand error")
	}
	if err := writeEnvCommandWithDeps(context.Background(), append(base, "--grant-project", "bad"), io.Discard, io.Discard, &fakeStarter{}, deps); err == nil {
		t.Fatal("expected write-env project grant error")
	}
	if err := writeEnvCommandWithDeps(context.Background(), append(base, "--grant-secret", "bad"), io.Discard, io.Discard, &fakeStarter{}, deps); err == nil {
		t.Fatal("expected write-env secret grant error")
	}
	if err := writeEnvCommandWithDeps(context.Background(), append(base, "--grant-convenience", "bad"), io.Discard, io.Discard, &fakeStarter{}, deps); err == nil {
		t.Fatal("expected write-env convenience grant error")
	}
	if err := writeEnvCommandWithDeps(context.Background(), append(base, "--grant-project", "1s", "--grant-secret", "2s"), io.Discard, io.Discard, &fakeStarter{}, deps); err == nil {
		t.Fatal("expected write-env grant conflict")
	}
	if err := checkRepoCommandWithDeps(context.Background(), []string{"--project-root", "~\x00bad"}, io.Discard, io.Discard, deps); err == nil {
		t.Fatal("expected check-repo project-root expand error")
	}

	if err := rejectWriteEnvSymlink("\x00", "bad path"); err == nil {
		t.Fatal("expected rejectWriteEnvSymlink inspect error")
	}
	tempBase := filepath.Join(t.TempDir(), "out.env")
	if err := os.Symlink("target", tempBase+".tmp"); err != nil {
		t.Fatalf("create temp symlink: %v", err)
	}
	if _, err := preflightWriteEnvDestination(context.Background(), t.TempDir(), tempBase, true, deps); err == nil {
		t.Fatal("expected temporary output symlink rejection")
	}
	if got := mergeRedactedItems([]string{"B"}, []string{"A"}); strings.Join(got, ",") != "A,B" {
		t.Fatalf("mergeRedactedItems = %#v", got)
	}
	fakeDeps := execDeps{
		AbsPath: func(path string) (string, error) {
			if path == "err" {
				return "", errors.New("abs fail")
			}
			return path, nil
		},
		EvalSymlinks: func(string) (string, error) { return "", errors.New("eval fail") },
	}
	if !pathInsideProjectForWrite("root/file", "root", fakeDeps) {
		t.Fatal("expected direct inside-project path")
	}
	if pathInsideProjectForWrite("x", "", fakeDeps) {
		t.Fatal("empty root should not be inside project")
	}
	if pathInsideProjectForWrite("err", "root", fakeDeps) {
		t.Fatal("abs error should not be inside project")
	}
	if pathInsideProjectForWrite("a/b", "root", fakeDeps) {
		t.Fatal("unresolvable parent walk should not be inside project")
	}
}

func TestCoverage100UpgradeBranches(t *testing.T) {
	restoreKeys := release.SetPinnedKeysForTest(strings.Repeat("00", 32))
	defer restoreKeys()

	deps := upgradeDeps{
		Executable: func() (string, error) { return "", errors.New("exe fail") },
		Upgrade: func(context.Context, release.UpgradeOptions) (release.UpgradeReport, error) {
			return release.UpgradeReport{}, nil
		},
		IsTerminal: func() bool { return true },
	}
	if err := upgradeCommandWithDeps(context.Background(), []string{"--version", "v9.9.9", "--yes"}, strings.NewReader(""), io.Discard, io.Discard, deps); err == nil {
		t.Fatal("expected executable error")
	}
	if err := upgradeCommandWithDeps(context.Background(), []string{"--bad"}, strings.NewReader(""), io.Discard, io.Discard, deps); err == nil {
		t.Fatal("expected upgrade parse error")
	}
	deps.Executable = func() (string, error) { return "/tmp/hasp", nil }
	deps.Upgrade = func(context.Context, release.UpgradeOptions) (release.UpgradeReport, error) {
		return release.UpgradeReport{}, errors.New("upgrade fail")
	}
	if err := upgradeCommandWithDeps(context.Background(), []string{"--version", "v9.9.9", "--yes"}, strings.NewReader(""), io.Discard, io.Discard, deps); err == nil {
		t.Fatal("expected upgrade execution error")
	}
	if confirmUpgrade(nil, io.Discard, "old", "new", "/tmp/hasp") {
		t.Fatal("nil stdin should decline upgrade")
	}
	if confirmUpgrade(errReader{err: errors.New("read fail")}, io.Discard, "old", "new", "/tmp/hasp") {
		t.Fatal("read error should decline upgrade")
	}
}
