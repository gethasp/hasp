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

	"github.com/gethasp/hasp/apps/server/internal/hooks"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestDoctorReportsIndividualHooksWhenVaultIsLocked(t *testing.T) {
	lockAppSeams(t)
	root := t.TempDir()
	if out, err := run("git", "-C", root, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := hooks.Install(root); err != nil {
		t.Fatal(err)
	}
	origOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = origOpen })
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, store.ErrKeyringUnavailable }
	readReport := func() doctorJSONReport {
		t.Helper()
		var out bytes.Buffer
		if err := doctorCommand(context.Background(), []string{"--json", "--project-root", root}, &out, nil); err != nil {
			t.Fatal(err)
		}
		var report doctorJSONReport
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		return report
	}
	got := readReport()
	if !got.HooksInstalled || !got.Hooks.Ready || got.Hooks.ScanState != "not_run" || got.RepoProtectionState != "vault_unavailable" {
		t.Fatalf("locked vault hid installed hooks or claimed protection: %+v", got)
	}
	plan, err := hooks.ResolveInstallPlan(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(plan.HooksDir, "pre-push")); err != nil {
		t.Fatal(err)
	}
	got = readReport()
	if got.HooksInstalled || got.Hooks.PreCommit.State != "ready" || got.Hooks.PrePush.State != "missing" || got.RepoProtectionState != "hooks_partial" {
		t.Fatalf("partial installation not explained: %+v", got)
	}
	var human bytes.Buffer
	if err := doctorCommand(context.Background(), []string{"--project-root", root}, &human, nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pre_commit", "pre_push", "missing", "hooks_partial", "not_run", "hasp project hooks"} {
		if !strings.Contains(human.String(), want) {
			t.Fatalf("human doctor missing %q: %s", want, human.String())
		}
	}
}

func TestProjectHooksRepairDoesNotOpenOrRebindVault(t *testing.T) {
	lockAppSeams(t)
	root := t.TempDir()
	if out, err := run("git", "-C", root, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	origOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = origOpen })
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		t.Error("hook repair attempted to open the vault")
		return nil, store.ErrKeyringUnavailable
	}
	var out bytes.Buffer
	if err := projectCommand(context.Background(), []string{"hooks", "--project-root", root, "--install", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var report hooks.Diagnostics
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Ready || report.ScanState != "not_run" {
		t.Fatalf("hook repair did not produce current executable hooks: %+v", report)
	}
}

func TestProjectHooksReportsRepairAndWriterFailures(t *testing.T) {
	lockAppSeams(t)
	root := t.TempDir()
	if out, err := run("git", "-C", root, "init"); err != nil {
		t.Fatalf("git init: %s: %v", out, err)
	}
	var out bytes.Buffer
	args := []string{"--project-root", root}
	if err := projectHooksCommand(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "hasp project hooks") || !strings.Contains(out.String(), "missing") {
		t.Fatalf("repair missing: %s", out.String())
	}
	if err := projectHooksCommand(context.Background(), args, matchErrWriter{match: "hasp project hooks"}); err == nil {
		t.Fatal("repair write error ignored")
	}
	if err := projectHooksCommand(context.Background(), args, errWriter{err: io.ErrClosedPipe}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("header write: %v", err)
	}
	for _, invalid := range [][]string{{"--invalid"}, {"unexpected"}, {"--project-root", "~another-user/repo"}} {
		if err := projectHooksCommand(context.Background(), invalid, io.Discard); err == nil {
			t.Fatalf("invalid arguments accepted: %v", invalid)
		}
	}
	oldInstall := installHooksFn
	t.Cleanup(func() { installHooksFn = oldInstall })
	installHooksFn = func(string) error { return io.ErrClosedPipe }
	if err := projectHooksCommand(context.Background(), append(args, "--install"), io.Discard); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("install error: %v", err)
	}
	if err := hooks.Install(root); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := projectHooksCommand(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ready") || strings.Contains(out.String(), "hasp project hooks") {
		t.Fatalf("ready report: %s", out.String())
	}
	handle := newSecretHandleForTests(t)
	oldOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = oldOpen })
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return handle, nil }
	report := buildDoctorReport(context.Background(), root, nil)
	if report.RepoProtectionState != "ready_to_scan" || report.Hooks.ScanState != "not_run" {
		t.Fatalf("ready doctor: %+v", report)
	}
}
