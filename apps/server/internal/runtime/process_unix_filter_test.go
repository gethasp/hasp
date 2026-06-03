//go:build unix

package runtime

import (
	"slices"
	"testing"
)

// TestFilterDaemonEnvStripsCredentials pins hasp-f373: no credential reaches the
// long-lived daemon's environment — neither the per-run session bearer token nor
// the vault-unlocking secrets (which are passed over a one-shot fd instead).
// Non-credential vars pass through.
func TestFilterDaemonEnvStripsCredentials(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"HASP_SESSION_TOKEN=secret-bearer",
		"HASP_MASTER_PASSWORD=pw",
		"HASP_BACKUP_PASSPHRASE=bp",
		"HOME=/home/x",
	}
	out := filterDaemonEnv(in)
	for _, kv := range out {
		for _, leak := range []string{"HASP_SESSION_TOKEN=", "HASP_MASTER_PASSWORD=", "HASP_BACKUP_PASSPHRASE="} {
			if len(kv) >= len(leak) && kv[:len(leak)] == leak {
				t.Fatalf("credential must not reach daemon env: %q", kv)
			}
		}
	}
	for _, want := range []string{"PATH=/usr/bin", "HOME=/home/x"} {
		if !slices.Contains(out, want) {
			t.Fatalf("daemon env should retain non-credential var %q", want)
		}
	}
}
