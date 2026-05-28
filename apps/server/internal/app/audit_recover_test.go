package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func writeHealthyAuditForRecoverTest(t *testing.T, home string, key []byte) {
	t.Helper()
	log := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(home, "audit.jsonl")}).WithKey(key)
	if _, err := log.Append(audit.EventInit, "tester", map[string]any{"ok": true}); err != nil {
		t.Fatalf("append event: %v", err)
	}
}

func resetAuditRecoverSeams(t *testing.T) {
	t.Helper()
	origReadFile := auditRecoverReadFileFn
	origMkdirAll := auditRecoverMkdirAllFn
	origStat := auditRecoverStatFn
	origRename := auditRecoverRenameFn
	origNewLog := auditRecoverNewLogFn
	origMarshal := auditRecoverMarshalJSONFn
	origWriteFile := auditRecoverWriteFileFn
	t.Cleanup(func() {
		auditRecoverReadFileFn = origReadFile
		auditRecoverMkdirAllFn = origMkdirAll
		auditRecoverStatFn = origStat
		auditRecoverRenameFn = origRename
		auditRecoverNewLogFn = origNewLog
		auditRecoverMarshalJSONFn = origMarshal
		auditRecoverWriteFileFn = origWriteFile
	})
}

func setupHealthyAuditRecoverCommandTest(t *testing.T) (home string, output string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv(paths.EnvHome, home)
	key := bytes.Repeat([]byte{10}, sha256.Size)
	setAuditHMACKey(key)
	writeHealthyAuditForRecoverTest(t, home, key)
	return home, filepath.Join(home, "recovery")
}

func TestAuditRecoverArchivesDegradedLogAndStartsFreshChain(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	key := bytes.Repeat([]byte{7}, sha256.Size)
	setAuditHMACKey(key)
	t.Cleanup(clearAuditHMACKey)

	log := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(home, "audit.jsonl")}).WithKey(key)
	if _, err := log.Append(audit.EventInit, "tester", map[string]any{"ok": true}); err != nil {
		t.Fatalf("append first event: %v", err)
	}
	file, err := os.OpenFile(filepath.Join(home, "audit.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open audit log for corruption: %v", err)
	}
	if _, err := file.WriteString("not-json\n"); err != nil {
		_ = file.Close()
		t.Fatalf("corrupt audit log: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close corrupted audit log: %v", err)
	}

	recoveryDir := filepath.Join(home, "recovery")
	var out bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{
		"recover",
		"--output", recoveryDir,
		"--reason", "duplicate append at sequence 889",
		"--json",
	}, &out); err != nil {
		t.Fatalf("audit recover: %v", err)
	}

	if _, err := os.Stat(filepath.Join(recoveryDir, "audit.jsonl")); err != nil {
		t.Fatalf("expected archived audit log: %v", err)
	}
	reportData, err := os.ReadFile(filepath.Join(recoveryDir, "recovery-report.json"))
	if err != nil {
		t.Fatalf("expected recovery report: %v", err)
	}
	var report auditRecoveryReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Status != "recovered" || report.ArchiveSHA256 == "" || report.FirstCorruptionAt == nil {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Reason != "duplicate append at sequence 889" {
		t.Fatalf("report reason = %q", report.Reason)
	}
	if err := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(recoveryDir, "audit.jsonl")}).WithKey(key).Verify(); err == nil {
		t.Fatal("archived degraded log should remain degraded")
	}
	fresh := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(home, "audit.jsonl")}).WithKey(key)
	if err := fresh.Verify(); err != nil {
		t.Fatalf("fresh audit log should verify: %v", err)
	}
	events, err := fresh.Events()
	if err != nil {
		t.Fatalf("read fresh events: %v", err)
	}
	if len(events) != 1 || events[0].Type != "audit.recovery.rotate" {
		t.Fatalf("fresh events = %+v", events)
	}
	if !strings.Contains(out.String(), `"status":"recovered"`) {
		t.Fatalf("json output missing recovered status: %s", out.String())
	}
}

func TestAuditRecoverRefusesHealthyChainWithoutForce(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	key := bytes.Repeat([]byte{8}, sha256.Size)
	setAuditHMACKey(key)
	t.Cleanup(clearAuditHMACKey)

	writeHealthyAuditForRecoverTest(t, home, key)
	err := auditCommandWithArgs(context.Background(), []string{"recover", "--output", filepath.Join(home, "recovery")}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "recovery not needed") {
		t.Fatalf("expected healthy refusal, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, "recovery", "audit.jsonl")); !os.IsNotExist(statErr) {
		t.Fatalf("healthy recover should not archive, stat err=%v", statErr)
	}
}

func TestAuditRecoverCoversValidationAndSetupErrors(t *testing.T) {
	lockAppSeams(t)

	origNewAuditLog := newAuditLogFn
	t.Cleanup(func() {
		newAuditLogFn = origNewAuditLog
		clearAuditHMACKey()
	})

	if err := auditRecoverCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected flag parse error")
	}
	if err := auditRecoverCommand(context.Background(), []string{"extra"}, io.Discard); err == nil {
		t.Fatal("expected usage error")
	}

	t.Setenv(paths.EnvHome, "")
	if err := auditRecoverCommand(context.Background(), nil, io.Discard); err == nil || !strings.Contains(err.Error(), "HASP_HOME") {
		t.Fatalf("expected explicit HASP_HOME error, got %v", err)
	}

	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	newAuditLogFn = func() (*audit.Log, error) { return nil, errors.New("audit open fail") }
	if err := auditRecoverCommand(context.Background(), nil, io.Discard); err == nil || !strings.Contains(err.Error(), "audit open fail") {
		t.Fatalf("expected audit log open error, got %v", err)
	}
	newAuditLogFn = origNewAuditLog

	if err := os.Mkdir(filepath.Join(home, "audit.jsonl"), 0o700); err != nil {
		t.Fatalf("make audit path directory: %v", err)
	}
	if err := auditRecoverCommand(context.Background(), []string{"--force"}, io.Discard); err == nil {
		t.Fatal("expected verify error for directory audit path")
	}
}

func TestAuditRecoverCoversOutputErrors(t *testing.T) {
	lockAppSeams(t)

	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	key := bytes.Repeat([]byte{9}, sha256.Size)
	setAuditHMACKey(key)
	t.Cleanup(clearAuditHMACKey)
	writeHealthyAuditForRecoverTest(t, home, key)

	if err := auditRecoverCommand(context.Background(), []string{"--force", "--output", "~\x00bad"}, io.Discard); err == nil {
		t.Fatal("expected output expansion error")
	}

	outputFile := filepath.Join(home, "not-a-dir")
	if err := os.WriteFile(outputFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write output file: %v", err)
	}
	if err := auditRecoverCommand(context.Background(), []string{"--force", "--output", outputFile}, io.Discard); err == nil {
		t.Fatal("expected create recovery dir error")
	}

	if err := auditRecoverCommand(context.Background(), []string{"--force", "--output", home}, io.Discard); err == nil || !strings.Contains(err.Error(), "active HASP home") {
		t.Fatalf("expected active home output refusal, got %v", err)
	}

	archiveExists := filepath.Join(home, "archive-exists")
	if err := os.MkdirAll(archiveExists, 0o700); err != nil {
		t.Fatalf("make archive output: %v", err)
	}
	if err := os.WriteFile(filepath.Join(archiveExists, "audit.jsonl"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write archive placeholder: %v", err)
	}
	if err := auditRecoverCommand(context.Background(), []string{"--force", "--output", archiveExists}, io.Discard); err == nil || !strings.Contains(err.Error(), "archive path already exists") {
		t.Fatalf("expected archive exists error, got %v", err)
	}

	reportExists := filepath.Join(home, "report-exists")
	if err := os.MkdirAll(reportExists, 0o700); err != nil {
		t.Fatalf("make report output: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reportExists, "recovery-report.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write report placeholder: %v", err)
	}
	if err := auditRecoverCommand(context.Background(), []string{"--force", "--output", reportExists}, io.Discard); err == nil || !strings.Contains(err.Error(), "recovery report already exists") {
		t.Fatalf("expected report exists error, got %v", err)
	}

	var out bytes.Buffer
	if err := auditRecoverCommand(context.Background(), []string{"--force"}, &out); err != nil {
		t.Fatalf("force recover with default output: %v", err)
	}
	if !strings.Contains(out.String(), "Audit recovered") || !strings.Contains(out.String(), "First corruption") {
		t.Fatalf("expected human recovery output, got %q", out.String())
	}
}

func TestAuditRecoverUsesVaultKeyAndRendersCorruptionSequence(t *testing.T) {
	lockAppSeams(t)

	origOpenVault := openVaultHandleFn
	t.Cleanup(func() {
		openVaultHandleFn = origOpenVault
		clearAuditHMACKey()
	})

	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
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

	log := audit.NewForPaths(paths.Paths{AuditPath: filepath.Join(home, "audit.jsonl")}).WithKey(handle.AuditHMACKey())
	if _, err := log.Append(audit.EventInit, "tester", map[string]any{"ok": true}); err != nil {
		t.Fatalf("append first event: %v", err)
	}
	file, err := os.OpenFile(filepath.Join(home, "audit.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open audit log for corruption: %v", err)
	}
	if _, err := file.WriteString("not-json\n"); err != nil {
		_ = file.Close()
		t.Fatalf("corrupt audit log: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close corrupted audit log: %v", err)
	}

	var out bytes.Buffer
	if err := auditRecoverCommand(context.Background(), []string{"--output", filepath.Join(home, "recovery")}, &out); err != nil {
		t.Fatalf("audit recover: %v", err)
	}
	if !strings.Contains(out.String(), "First corruption") || strings.Contains(out.String(), "First corruption  -") {
		t.Fatalf("expected rendered corruption sequence, got %q", out.String())
	}
}

func TestAuditRecoverCoversSeamedFailureEdges(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, home string, output string)
		want  string
	}{
		{
			name: "read audit log",
			setup: func(t *testing.T, _ string, _ string) {
				auditRecoverReadFileFn = func(string) ([]byte, error) {
					return nil, errors.New("read denied")
				}
			},
			want: "read audit log",
		},
		{
			name: "archive stat",
			setup: func(t *testing.T, _ string, _ string) {
				auditRecoverStatFn = func(string) (os.FileInfo, error) {
					return nil, errors.New("stat denied")
				}
			},
			want: "check archive path",
		},
		{
			name: "report stat",
			setup: func(t *testing.T, _ string, _ string) {
				calls := 0
				auditRecoverStatFn = func(string) (os.FileInfo, error) {
					calls++
					if calls == 1 {
						return nil, os.ErrNotExist
					}
					return nil, errors.New("report stat denied")
				}
			},
			want: "check recovery report path",
		},
		{
			name: "archive rename",
			setup: func(t *testing.T, _ string, _ string) {
				auditRecoverRenameFn = func(string, string) error {
					return errors.New("rename denied")
				}
			},
			want: "archive degraded audit log",
		},
		{
			name: "marker append restores archive",
			setup: func(t *testing.T, _ string, _ string) {
				auditRecoverNewLogFn = func(paths.Paths) *audit.Log {
					return audit.NewForPaths(paths.Paths{AuditPath: t.TempDir()})
				}
			},
			want: "append recovery marker",
		},
		{
			name: "marker append restore failure",
			setup: func(t *testing.T, _ string, _ string) {
				auditRecoverNewLogFn = func(paths.Paths) *audit.Log {
					return audit.NewForPaths(paths.Paths{AuditPath: t.TempDir()})
				}
				calls := 0
				auditRecoverRenameFn = func(from string, to string) error {
					calls++
					if calls == 1 {
						return os.Rename(from, to)
					}
					return errors.New("restore denied")
				}
			},
			want: "restore archived audit log",
		},
		{
			name: "marshal report",
			setup: func(t *testing.T, _ string, _ string) {
				auditRecoverMarshalJSONFn = func(any, string, string) ([]byte, error) {
					return nil, errors.New("marshal denied")
				}
			},
			want: "marshal denied",
		},
		{
			name: "write report",
			setup: func(t *testing.T, _ string, _ string) {
				auditRecoverWriteFileFn = func(string, []byte, os.FileMode) error {
					return errors.New("write denied")
				}
			},
			want: "write recovery report",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lockAppSeams(t)
			resetAuditRecoverSeams(t)
			_, output := setupHealthyAuditRecoverCommandTest(t)
			t.Cleanup(clearAuditHMACKey)
			tc.setup(t, "", output)
			err := auditRecoverCommand(context.Background(), []string{"--force", "--output", output}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}
