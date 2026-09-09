package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/gethasp/hasp/apps/server/internal/store"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/reposcan"
)

func TestCheckRepoPartialResultRetainsMatchesAndFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unreadable-file replay requires a non-root user")
	}
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "synthetic scan password")
	for _, args := range [][]string{{"init"}, {"set", "--name", "scan_token", "--value", "synthetic-scan-token"}} {
		if err := Run(context.Background(), args, strings.NewReader(""), io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	for _, path := range []string{"a-leak", "b-unreadable", "c-leak"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte("synthetic-scan-token"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unreadable := filepath.Join(root, "b-unreadable")
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })
	deps := defaultExecDeps()
	for _, format := range []string{"human", "json"} {
		for _, override := range []bool{false, true} {
			args := []string{"--project-root", root}
			if format == "json" {
				args = append(args, "--json")
			}
			if override {
				args = append(args, "--allow-managed-secrets")
			}
			var out bytes.Buffer
			err := checkRepoCommandWithDeps(context.Background(), args, &out, io.Discard, deps)
			if err == nil || appErrorExitCode(err) != 4 || classifyAppError(err).Code != errCodeScanIncomplete {
				t.Fatalf("%s override=%t: incomplete scan passed: %v", format, override, err)
			}
			if format == "json" {
				var result reposcan.Result
				if err := json.Unmarshal(out.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Complete || len(result.Matches) != 2 || len(result.Issues) != 1 {
					t.Fatalf("partial JSON lost evidence: %+v", result)
				}
				if result.Stats.SourcesEnumerated != 3 || result.Stats.SourcesScanned != 2 || result.Stats.Issues != 1 || result.Stats.CommandMS < result.Stats.TotalMS || result.Stats.VaultMS <= 0 {
					t.Fatalf("partial JSON lost scan measurements: %+v", result.Stats)
				}
			} else if !strings.Contains(out.String(), "incomplete") || !strings.Contains(out.String(), "a-leak") || !strings.Contains(out.String(), "c-leak") || !strings.Contains(out.String(), "b-unreadable") || strings.Contains(out.String(), "[ok]") {
				t.Fatalf("partial human output lost evidence: %s", out.String())
			}
		}
	}
}

func TestRepoScanOutputRetainsCoverageDetailsAndWriteErrors(t *testing.T) {
	result := reposcan.Result{
		Skipped: []reposcan.Skipped{{Path: "large.bin", Reason: "oversized", Size: 42}},
		Issues:  []reposcan.Issue{{Path: "unreadable", Reason: "read_failed", Detail: "permission denied"}},
		Deleted: []string{"removed.txt"},
	}
	var out bytes.Buffer
	if err := renderRepoScanResult(&out, "project", result, false, ""); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"Coverage gaps", "large.bin: oversized (42 bytes)", "unreadable: read_failed (permission denied)", "Deleted from working tree", "removed.txt"} {
		if !strings.Contains(out.String(), text) {
			t.Fatalf("missing %q: %s", text, out.String())
		}
		if err := renderRepoScanResult(matchErrWriter{match: text}, "project", result, false, ""); err == nil {
			t.Fatalf("write failure ignored at %q", text)
		}
	}
}

func TestCheckRepoReturnsOutputFailure(t *testing.T) {
	lockAppSeams(t)
	oldOpen := openVaultHandleFn
	t.Cleanup(func() { openVaultHandleFn = oldOpen })
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return nil, store.ErrVaultNotInitialized }
	err := checkRepoCommandWithDeps(context.Background(), []string{"--project-root", t.TempDir(), "--json"}, errWriter{err: io.ErrClosedPipe}, io.Discard, defaultExecDeps())
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output failure: %v", err)
	}
}
