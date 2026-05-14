package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectHaspPathDiagnosticsFindsShadowingAndNewerHomebrewCandidate(t *testing.T) {
	lockAppSeams(t)
	restorePathDiagnosticSeams(t)

	tmp := t.TempDir()
	localBin := filepath.Join(tmp, "local", "bin")
	brewBin := filepath.Join(tmp, "homebrew", "bin")
	brewCellarBin := filepath.Join(tmp, "homebrew", "Cellar", "hasp", "1.0.6", "bin")
	for _, dir := range []string{localBin, brewBin, brewCellarBin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	current := filepath.Join(localBin, "hasp")
	if err := os.WriteFile(current, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write current hasp: %v", err)
	}
	brewTarget := filepath.Join(brewCellarBin, "hasp")
	if err := os.WriteFile(brewTarget, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write brew hasp: %v", err)
	}
	if err := os.Symlink(brewTarget, filepath.Join(brewBin, "hasp")); err != nil {
		t.Fatalf("symlink brew hasp: %v", err)
	}

	pathDiagnosticsExecutableFn = func() (string, error) { return current, nil }
	pathDiagnosticsLookupEnvFn = func(key string) string {
		switch key {
		case "PATH":
			return strings.Join([]string{localBin, brewBin}, string(os.PathListSeparator))
		default:
			return ""
		}
	}

	report := detectHaspPathDiagnostics("1.0.4")
	if report.Shadowed {
		t.Fatalf("current executable is first on PATH, should not be shadowed: %+v", report)
	}
	if !report.HasNewer {
		t.Fatalf("expected newer Homebrew candidate inferred from Cellar path: %+v", report)
	}
	if !strings.Contains(report.Warning, "newer hasp 1.0.6") || !strings.Contains(report.Warning, "hash -r") {
		t.Fatalf("warning should name newer version and shell hash fix, got %q", report.Warning)
	}
}

func TestDetectHaspPathDiagnosticsFindsEarlierShadowingWithoutExecutingCandidate(t *testing.T) {
	lockAppSeams(t)
	restorePathDiagnosticSeams(t)

	tmp := t.TempDir()
	earlierBin := filepath.Join(tmp, "earlier")
	currentBin := filepath.Join(tmp, "current")
	for _, dir := range []string{earlierBin, currentBin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	earlier := filepath.Join(earlierBin, "hasp")
	current := filepath.Join(currentBin, "hasp")
	if err := os.WriteFile(earlier, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil {
		t.Fatalf("write earlier hasp: %v", err)
	}
	if err := os.WriteFile(current, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write current hasp: %v", err)
	}

	pathDiagnosticsExecutableFn = func() (string, error) { return current, nil }
	pathDiagnosticsLookupEnvFn = func(key string) string {
		switch key {
		case "PATH":
			return strings.Join([]string{earlierBin, currentBin}, string(os.PathListSeparator))
		default:
			return ""
		}
	}

	report := detectHaspPathDiagnostics("1.0.6")
	if !report.Shadowed {
		t.Fatalf("expected current executable to be shadowed by earlier PATH entry: %+v", report)
	}
	if report.HasNewer {
		t.Fatalf("did not expect newer version when version is not safely inferable: %+v", report)
	}
	if !strings.Contains(report.Warning, earlier) || !strings.Contains(report.Warning, "remove the earlier binary") {
		t.Fatalf("warning should identify earlier path and remediation, got %q", report.Warning)
	}
}

func TestDetectHaspPathDiagnosticsHonorsSkipEnv(t *testing.T) {
	lockAppSeams(t)
	restorePathDiagnosticSeams(t)

	pathDiagnosticsExecutableFn = func() (string, error) { return "/tmp/hasp", nil }
	pathDiagnosticsLookupEnvFn = func(string) string { return "1" }

	report := detectHaspPathDiagnostics("1.0.6")
	if report.Warning != "" || report.Executable != "" {
		t.Fatalf("expected diagnostics to be skipped: %+v", report)
	}
}

func TestVersionVerboseIncludesPathDiagnostics(t *testing.T) {
	lockAppSeams(t)
	restorePathDiagnosticSeams(t)

	tmp := t.TempDir()
	earlierBin := filepath.Join(tmp, "earlier")
	currentBin := filepath.Join(tmp, "current")
	for _, dir := range []string{earlierBin, currentBin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	earlier := filepath.Join(earlierBin, "hasp")
	current := filepath.Join(currentBin, "hasp")
	for _, path := range []string{earlier, current} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	pathDiagnosticsExecutableFn = func() (string, error) { return current, nil }
	pathDiagnosticsLookupEnvFn = func(key string) string {
		switch key {
		case "PATH":
			return strings.Join([]string{earlierBin, currentBin}, string(os.PathListSeparator))
		default:
			return ""
		}
	}

	ctx := contextWithGlobalFlags(context.Background(), globalFlags{verbose: true})
	var human bytes.Buffer
	if err := versionCommand(ctx, nil, &human); err != nil {
		t.Fatalf("versionCommand verbose: %v", err)
	}
	if !strings.Contains(human.String(), "warning: this hasp executable is shadowed by") {
		t.Fatalf("expected human warning, got %q", human.String())
	}

	var encoded bytes.Buffer
	if err := versionCommand(ctx, []string{"--json"}, &encoded); err != nil {
		t.Fatalf("versionCommand verbose json: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded.Bytes(), &payload); err != nil {
		t.Fatalf("decode version json: %v\nraw: %s", err, encoded.String())
	}
	if _, ok := payload["path_diagnostics"].(map[string]any); !ok {
		t.Fatalf("expected path_diagnostics in verbose json payload: %+v", payload)
	}
}

func TestDoctorReportIncludesPathResolutionFailure(t *testing.T) {
	lockAppSeams(t)
	restorePathDiagnosticSeams(t)

	tmp := t.TempDir()
	t.Setenv("HASP_HOME", filepath.Join(tmp, "home"))
	earlierBin := filepath.Join(tmp, "earlier")
	currentBin := filepath.Join(tmp, "current")
	for _, dir := range []string{earlierBin, currentBin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	earlier := filepath.Join(earlierBin, "hasp")
	current := filepath.Join(currentBin, "hasp")
	for _, path := range []string{earlier, current} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	pathDiagnosticsExecutableFn = func() (string, error) { return current, nil }
	pathDiagnosticsLookupEnvFn = func(key string) string {
		switch key {
		case "PATH":
			return strings.Join([]string{earlierBin, currentBin}, string(os.PathListSeparator))
		default:
			return ""
		}
	}

	report := buildDoctorReport(context.Background(), tmp, nil)
	if !report.PathShadowed {
		t.Fatalf("expected doctor report to flag path shadowing: %+v", report)
	}
	if !strings.Contains(report.pathDetail, earlier) {
		t.Fatalf("expected doctor detail to identify earlier executable, got %q", report.pathDetail)
	}
}

func TestDoctorReportIncludesBrokenManagedAgentWrapper(t *testing.T) {
	lockAppSeams(t)
	restorePathDiagnosticSeams(t)

	tmp := t.TempDir()
	haspHome := filepath.Join(tmp, ".hasp")
	t.Setenv("HASP_HOME", haspHome)
	wrapperDir := filepath.Join(haspHome, "bin")
	if err := os.MkdirAll(wrapperDir, 0o700); err != nil {
		t.Fatalf("mkdir wrapper dir: %v", err)
	}
	wrapper := filepath.Join(wrapperDir, "hasp-agent-codex-cli")
	legacy := []byte("#!/usr/bin/env bash\n# hasp-managed agent wrapper\nset -euo pipefail\nexport HASP_HOME=\"" + haspHome + "\"\nexec \"" + filepath.Join(tmp, "missing", "hasp") + "\" agent mcp \"codex-cli\" \"$@\"\n")
	if err := os.WriteFile(wrapper, legacy, 0o700); err != nil {
		t.Fatalf("write legacy wrapper: %v", err)
	}

	report := buildDoctorReport(context.Background(), tmp, nil)
	if report.AgentMCPWrappersOK {
		t.Fatalf("expected doctor report to flag broken managed MCP wrapper: %+v", report)
	}
	if !strings.Contains(report.agentMCPWrapperDetail, "hasp-agent-codex-cli") || !strings.Contains(report.agentMCPWrapperDetail, "re-run hasp agent connect") {
		t.Fatalf("expected wrapper remediation detail, got %q", report.agentMCPWrapperDetail)
	}
}

func TestPathDiagnosticsResidualBranches(t *testing.T) {
	lockAppSeams(t)
	restorePathDiagnosticSeams(t)

	tmp := t.TempDir()
	currentBin := filepath.Join(tmp, "current")
	otherBin := filepath.Join(tmp, "other")
	if err := os.MkdirAll(currentBin, 0o755); err != nil {
		t.Fatalf("mkdir current: %v", err)
	}
	if err := os.MkdirAll(otherBin, 0o755); err != nil {
		t.Fatalf("mkdir other: %v", err)
	}
	current := filepath.Join(currentBin, "hasp")
	other := filepath.Join(otherBin, "hasp")
	if err := os.WriteFile(current, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write current: %v", err)
	}
	if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write other: %v", err)
	}
	pathDiagnosticsExecutableFn = func() (string, error) { return current, nil }
	pathDiagnosticsLookupEnvFn = func(key string) string {
		if key == "PATH" {
			return strings.Join([]string{"", currentBin, currentBin, otherBin}, string(os.PathListSeparator))
		}
		return ""
	}
	pathDiagnosticsEvalSymlinks = func(path string) (string, error) { return "", os.ErrNotExist }
	report := detectHaspPathDiagnostics("1.0.6")
	if report.Warning == "" || !strings.Contains(report.Warning, "multiple hasp executables") {
		t.Fatalf("expected multiple executable warning: %+v", report)
	}

	pathDiagnosticsLookupEnvFn = func(key string) string {
		if key == "PATH" {
			return ""
		}
		return ""
	}
	report = detectHaspPathDiagnostics("1.0.6")
	if report.Executable == "" || len(report.Candidates) != 0 {
		t.Fatalf("expected executable-only report: %+v", report)
	}
	pathDiagnosticsExecutableFn = func() (string, error) { return filepath.Join(tmp, "not-hasp"), nil }
	if report := detectHaspPathDiagnostics("1.0.6"); report.Executable != "" {
		t.Fatalf("non hasp executable should be ignored: %+v", report)
	}
	if looksLikeSemver("1..2") || looksLikeSemver("1.2.x") {
		t.Fatal("bad semver values should be rejected")
	}
	if compareSemverParts([3]int{1, 2, 3}, [3]int{1, 3, 0}) >= 0 {
		t.Fatal("semver compare less-than branch failed")
	}
}

func TestManagedWrapperDiagnosticsResidualBranches(t *testing.T) {
	lockAppSeams(t)
	tmp := t.TempDir()
	haspHome := filepath.Join(tmp, ".hasp")
	t.Setenv("HASP_HOME", haspHome)
	wrapperDir := filepath.Join(haspHome, "bin")
	if err := os.MkdirAll(wrapperDir, 0o700); err != nil {
		t.Fatalf("mkdir wrapper dir: %v", err)
	}
	validHasp := filepath.Join(tmp, "hasp")
	if err := os.WriteFile(validHasp, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatalf("write valid hasp: %v", err)
	}
	if got := managedWrapperConfiguredPath([]byte("no match")); got != "" {
		t.Fatalf("unexpected configured path = %q", got)
	}
	if got := legacyManagedWrapperConfiguredPath([]byte("no match")); got != "" {
		t.Fatalf("unexpected legacy configured path = %q", got)
	}
	wrappers := map[string][]byte{
		"hasp-agent-no-marker": []byte("configured_hasp=\"/missing\"\n"),
		"hasp-agent-empty":     []byte("# hasp-managed agent wrapper\nconfigured_hasp=\"\"\n"),
		"hasp-agent-bare":      []byte("# hasp-managed agent wrapper\nconfigured_hasp=\"hasp\"\n"),
		"hasp-agent-valid":     []byte("# hasp-managed agent wrapper\nconfigured_hasp=\"" + validHasp + "\"\n"),
	}
	for name, data := range wrappers {
		if err := os.WriteFile(filepath.Join(wrapperDir, name), data, 0o700); err != nil {
			t.Fatalf("write wrapper %s: %v", name, err)
		}
	}
	if warning := detectManagedAgentMCPWrapperProblems(); warning != "" {
		t.Fatalf("valid/ignored wrappers should not warn: %q", warning)
	}
}

func TestManagedWrapperDiagnosticsDefaultsHomeWhenHASPHomeUnset(t *testing.T) {
	lockAppSeams(t)
	oldHomeDir := agentWrapperUserHomeDir
	t.Cleanup(func() { agentWrapperUserHomeDir = oldHomeDir })

	tmp := t.TempDir()
	t.Setenv("HASP_HOME", "")
	t.Setenv("HOME", tmp)
	agentWrapperUserHomeDir = func() (string, error) { return "", errors.New("home failed") }
	if warning := detectManagedAgentMCPWrapperProblems(); warning != "" {
		t.Fatalf("home lookup failure should not warn: %q", warning)
	}
	agentWrapperUserHomeDir = func() (string, error) { return tmp, nil }
	if warning := detectManagedAgentMCPWrapperProblems(); warning != "" {
		t.Fatalf("empty default wrapper directory should not warn: %q", warning)
	}
}

func TestPathDiagnosticsRemainingHelperBranches(t *testing.T) {
	lockAppSeams(t)
	restorePathDiagnosticSeams(t)

	pathDiagnosticsStatFn = func(path string) (os.FileInfo, error) {
		return nil, errors.New("stat failed")
	}
	if got := haspPathCandidates(t.TempDir()); len(got) != 0 {
		t.Fatalf("stat failures should skip candidates: %+v", got)
	}
	if got := cleanComparablePath(" "); got != "" {
		t.Fatalf("blank clean path = %q", got)
	}
	candidates := []haspPathCandidate{
		{Path: "/opt/hasp/1.0.0/bin/hasp", Version: "1.0.0"},
		{Path: "/opt/hasp/1.0.1/bin/hasp", Version: "1.0.1"},
	}
	if got := newestOtherCandidate(candidates, cleanComparablePath("/opt/hasp/1.0.1/bin/hasp"), "1.0.1"); got.Path != "" {
		t.Fatalf("no newer candidate expected: %+v", got)
	}
	if warning := buildHaspPathWarning(haspPathDiagnostics{}, haspPathCandidate{}, "1.0.1"); warning != "" {
		t.Fatalf("empty warning = %q", warning)
	}
	if compareSemverParts([3]int{1, 0, 0}, [3]int{1, 0, 0}) != 0 {
		t.Fatal("equal semver compare failed")
	}
}

func restorePathDiagnosticSeams(t *testing.T) {
	t.Helper()
	pathDiagnosticsExecutableFn = os.Executable
	pathDiagnosticsLookupEnvFn = os.Getenv
	pathDiagnosticsStatFn = os.Stat
	pathDiagnosticsEvalSymlinks = filepath.EvalSymlinks
	t.Cleanup(func() {
		pathDiagnosticsExecutableFn = os.Executable
		pathDiagnosticsLookupEnvFn = os.Getenv
		pathDiagnosticsStatFn = os.Stat
		pathDiagnosticsEvalSymlinks = filepath.EvalSymlinks
	})
}
