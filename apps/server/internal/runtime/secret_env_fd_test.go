//go:build unix

package runtime

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestLoadDaemonSecretEnvFromFD verifies the daemon reads its unlocking secrets
// from the inherited fd (hasp-f373). Uses a bare fd (syscall.Open) so no *os.File
// competes with loadDaemonSecretEnvFromFD for ownership of the descriptor.
func TestLoadDaemonSecretEnvFromFD(t *testing.T) {
	blobPath := filepath.Join(t.TempDir(), "blob")
	blob := encodeSecretEnvBlob([]string{
		"HASP_MASTER_PASSWORD=pw-from-fd",
		"HASP_BACKUP_PASSPHRASE=bp-from-fd",
	})
	if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	fd, err := syscall.Open(blobPath, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open blob fd: %v", err)
	}
	// loadDaemonSecretEnvFromFD takes ownership of fd and closes it.

	t.Setenv(secretEnvFDVar, strconv.Itoa(fd))
	daemonSecretEnvMu.Lock()
	daemonSecretEnv = nil
	daemonSecretEnvMu.Unlock()
	t.Cleanup(func() {
		daemonSecretEnvMu.Lock()
		daemonSecretEnv = nil
		daemonSecretEnvMu.Unlock()
	})

	loadDaemonSecretEnvFromFD()

	if got := daemonSecretGetenv("HASP_MASTER_PASSWORD"); got != "pw-from-fd" {
		t.Fatalf("master from fd: %q", got)
	}
	if got := daemonSecretGetenv("HASP_BACKUP_PASSPHRASE"); got != "bp-from-fd" {
		t.Fatalf("backup from fd: %q", got)
	}
	if os.Getenv(secretEnvFDVar) != "" {
		t.Fatal("secret env fd marker should be unset after load")
	}
}

func TestLoadDaemonSecretEnvFromFDNoopBranches(t *testing.T) {
	for _, raw := range []string{"", "not-a-fd", "-1"} {
		name := strings.ReplaceAll(raw, "-", "neg")
		if name == "" {
			name = "unset"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv(secretEnvFDVar, raw)
			daemonSecretEnvMu.Lock()
			daemonSecretEnv = nil
			daemonSecretEnvMu.Unlock()
			loadDaemonSecretEnvFromFD()
			daemonSecretEnvMu.RLock()
			got := daemonSecretEnv
			daemonSecretEnvMu.RUnlock()
			if got != nil {
				t.Fatalf("daemonSecretEnv = %#v", got)
			}
		})
	}
}

func TestLoadDaemonSecretEnvFromFDErrorsLeaveNoParsedSecrets(t *testing.T) {
	dir := t.TempDir()
	fd, err := syscall.Open(dir, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open dir fd: %v", err)
	}
	t.Setenv(secretEnvFDVar, strconv.Itoa(fd))
	daemonSecretEnvMu.Lock()
	daemonSecretEnv = nil
	daemonSecretEnvMu.Unlock()

	loadDaemonSecretEnvFromFD()

	daemonSecretEnvMu.RLock()
	got := daemonSecretEnv
	daemonSecretEnvMu.RUnlock()
	if got != nil {
		t.Fatalf("daemonSecretEnv = %#v", got)
	}
}
