package app

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// TestBackupArgvSecret_ExportRejectsArgvPassphrase verifies that passing
// --recovery-passphrase on the command line is rejected with a message
// that names the safer alternatives.
func TestBackupArgvSecret_ExportRejectsArgvPassphrase(t *testing.T) {
	err := exportBackupCommand(context.Background(),
		[]string{"--output", "/tmp/unused.json", "--recovery-passphrase", "pp"},
		io.Discard)
	if err == nil {
		t.Fatal("expected error for --recovery-passphrase on argv, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "argv") {
		t.Errorf("error missing 'argv': %q", msg)
	}
	if !strings.Contains(msg, "--recovery-passphrase-stdin") {
		t.Errorf("error missing '--recovery-passphrase-stdin': %q", msg)
	}
}

// TestBackupArgvSecret_ExportStdin verifies that --recovery-passphrase-stdin
// reads the passphrase from stdin.
func TestBackupArgvSecret_ExportStdin(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	t.Setenv("HASP_BACKUP_PASSPHRASE", "")

	keyring := &memorySetupKeyring{}
	origNewStore := newVaultStoreFn
	t.Cleanup(func() { newVaultStoreFn = origNewStore })
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	backupPath := t.TempDir() + "/backup.json"

	origStdin := stdinReaderFn
	t.Cleanup(func() { stdinReaderFn = origStdin })
	stdinReaderFn = func() io.Reader { return strings.NewReader("backup-passphrase\n") }

	if err := exportBackupCommand(context.Background(),
		[]string{"--output", backupPath, "--recovery-passphrase-stdin"},
		io.Discard); err != nil {
		t.Fatalf("export-backup --recovery-passphrase-stdin: %v", err)
	}
}

// TestBackupArgvSecret_ExportFD verifies that --recovery-passphrase-fd N reads
// the passphrase from file descriptor N.
func TestBackupArgvSecret_ExportFD(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	t.Setenv("HASP_BACKUP_PASSPHRASE", "")

	keyring := &memorySetupKeyring{}
	origNewStore := newVaultStoreFn
	t.Cleanup(func() { newVaultStoreFn = origNewStore })
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	backupPath := t.TempDir() + "/backup_fd.json"

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := io.WriteString(w, "backup-passphrase\n"); err != nil {
		t.Fatalf("write pipe: %v", err)
	}
	w.Close()

	origOpenFD := openFDFn
	t.Cleanup(func() { openFDFn = origOpenFD })
	openFDFn = func(fd uintptr) *os.File { return r }

	if err := exportBackupCommand(context.Background(),
		[]string{"--output", backupPath, "--recovery-passphrase-fd", "3"},
		io.Discard); err != nil {
		t.Fatalf("export-backup --recovery-passphrase-fd: %v", err)
	}
	r.Close()
}

// TestBackupArgvSecret_RestoreRejectsArgvPassphrase verifies that passing
// --recovery-passphrase on argv is rejected.
func TestBackupArgvSecret_RestoreRejectsArgvPassphrase(t *testing.T) {
	err := restoreBackupCommand(context.Background(),
		[]string{"--input", "/tmp/unused.json", "--recovery-passphrase", "pp"},
		io.Discard)
	if err == nil {
		t.Fatal("expected error for --recovery-passphrase on argv, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "argv") {
		t.Errorf("error missing 'argv': %q", msg)
	}
	if !strings.Contains(msg, "--recovery-passphrase-stdin") {
		t.Errorf("error missing '--recovery-passphrase-stdin': %q", msg)
	}
}

// TestBackupArgvSecret_RestoreRejectsArgvMasterPassword verifies that passing
// --master-password on argv is rejected.
func TestBackupArgvSecret_RestoreRejectsArgvMasterPassword(t *testing.T) {
	err := restoreBackupCommand(context.Background(),
		[]string{"--input", "/tmp/unused.json", "--master-password", "pw"},
		io.Discard)
	if err == nil {
		t.Fatal("expected error for --master-password on argv, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "argv") {
		t.Errorf("error missing 'argv': %q", msg)
	}
	if !strings.Contains(msg, "--recovery-passphrase-stdin") {
		t.Errorf("error missing '--recovery-passphrase-stdin': %q", msg)
	}
}

// TestBackupArgvSecret_RestoreStdin verifies that --recovery-passphrase-stdin
// and HASP_MASTER_PASSWORD env var work together for restore.
func TestBackupArgvSecret_RestoreStdin(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	t.Setenv("HASP_BACKUP_PASSPHRASE", "")

	keyring := &memorySetupKeyring{}
	origNewStore := newVaultStoreFn
	t.Cleanup(func() { newVaultStoreFn = origNewStore })
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	backupPath := t.TempDir() + "/backup_restore.json"

	origStdin := stdinReaderFn
	t.Cleanup(func() { stdinReaderFn = origStdin })
	stdinReaderFn = func() io.Reader { return strings.NewReader("backup-passphrase\n") }

	if err := exportBackupCommand(context.Background(),
		[]string{"--output", backupPath, "--recovery-passphrase-stdin"},
		io.Discard); err != nil {
		t.Fatalf("export-backup for restore test: %v", err)
	}

	restoreHome := t.TempDir()
	t.Setenv("HASP_HOME", restoreHome)
	t.Setenv("HASP_MASTER_PASSWORD", "restored-password")

	stdinReaderFn = func() io.Reader { return strings.NewReader("backup-passphrase\n") }

	if err := restoreBackupCommand(context.Background(),
		[]string{"--input", backupPath, "--recovery-passphrase-stdin"},
		io.Discard); err != nil {
		t.Fatalf("restore-backup --recovery-passphrase-stdin: %v", err)
	}
}

// TestBackupArgvSecret_RestoreFD verifies that --recovery-passphrase-fd N works
// for restore-backup.
func TestBackupArgvSecret_RestoreFD(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	t.Setenv("HASP_BACKUP_PASSPHRASE", "")

	keyring := &memorySetupKeyring{}
	origNewStore := newVaultStoreFn
	t.Cleanup(func() { newVaultStoreFn = origNewStore })
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}

	backupPath := t.TempDir() + "/backup_restore_fd.json"

	// Export first using stdin seam.
	origStdin := stdinReaderFn
	t.Cleanup(func() { stdinReaderFn = origStdin })
	stdinReaderFn = func() io.Reader { return strings.NewReader("backup-passphrase\n") }

	if err := exportBackupCommand(context.Background(),
		[]string{"--output", backupPath, "--recovery-passphrase-stdin"},
		io.Discard); err != nil {
		t.Fatalf("export-backup for fd restore test: %v", err)
	}

	restoreHome := t.TempDir()
	t.Setenv("HASP_HOME", restoreHome)
	t.Setenv("HASP_MASTER_PASSWORD", "restored-password")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := io.WriteString(w, "backup-passphrase\n"); err != nil {
		t.Fatalf("write pipe: %v", err)
	}
	w.Close()

	origOpenFD := openFDFn
	t.Cleanup(func() { openFDFn = origOpenFD })
	openFDFn = func(fd uintptr) *os.File { return r }

	if err := restoreBackupCommand(context.Background(),
		[]string{"--input", backupPath, "--recovery-passphrase-fd", "3"},
		io.Discard); err != nil {
		t.Fatalf("restore-backup --recovery-passphrase-fd: %v", err)
	}
	r.Close()
}

// TestBackupHelpExamples_ExportContainsStdin verifies that help for export-backup
// mentions --recovery-passphrase-stdin and does NOT show the unsafe argv form.
func TestBackupHelpExamples_ExportContainsStdin(t *testing.T) {
	if !strings.Contains(exportBackupHelpText, "--recovery-passphrase-stdin") {
		t.Error("exportBackupHelpText missing --recovery-passphrase-stdin")
	}
	if strings.Contains(exportBackupHelpText, "--recovery-passphrase 'pp'") ||
		strings.Contains(exportBackupHelpText, "--recovery-passphrase pp") ||
		strings.Contains(exportBackupHelpText, "--recovery-passphrase 'passphrase'") ||
		strings.Contains(exportBackupHelpText, "--recovery-passphrase passphrase") {
		t.Error("exportBackupHelpText still shows unsafe argv form --recovery-passphrase <value>")
	}
}

// TestBackupHelpExamples_RestoreContainsStdin verifies that help for restore-backup
// mentions --recovery-passphrase-stdin and does NOT show the unsafe argv forms.
func TestBackupHelpExamples_RestoreContainsStdin(t *testing.T) {
	if !strings.Contains(restoreBackupHelpText, "--recovery-passphrase-stdin") {
		t.Error("restoreBackupHelpText missing --recovery-passphrase-stdin")
	}
	if strings.Contains(restoreBackupHelpText, "--recovery-passphrase 'passphrase'") ||
		strings.Contains(restoreBackupHelpText, "--recovery-passphrase passphrase") {
		t.Error("restoreBackupHelpText still shows unsafe argv --recovery-passphrase form")
	}
	if strings.Contains(restoreBackupHelpText, "--master-password 'new-password'") ||
		strings.Contains(restoreBackupHelpText, "--master-password new-password") {
		t.Error("restoreBackupHelpText still shows unsafe argv --master-password form")
	}
}
