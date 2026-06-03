package runtime

import (
	"testing"
)

func TestSecretEnvBlobRoundTrip(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"HASP_MASTER_PASSWORD=master-secret\nignored",
		"HASP_BACKUP_PASSPHRASE=backup-secret",
	}
	if !hasSensitiveEnv(environ) {
		t.Fatal("hasSensitiveEnv should detect the sensitive vars")
	}
	if hasSensitiveEnv([]string{"PATH=/usr/bin"}) {
		t.Fatal("hasSensitiveEnv false positive")
	}
	parsed := parseSecretEnvBlob(encodeSecretEnvBlob(environ))
	if parsed["HASP_MASTER_PASSWORD"] != "master-secret" {
		t.Fatalf("master round-trip: %q", parsed["HASP_MASTER_PASSWORD"])
	}
	if parsed["HASP_BACKUP_PASSPHRASE"] != "backup-secret" {
		t.Fatalf("backup round-trip: %q", parsed["HASP_BACKUP_PASSPHRASE"])
	}
	if _, ok := parsed["PATH"]; ok {
		t.Fatal("non-sensitive var must not be in the blob")
	}
}

func TestParseSecretEnvBlobIgnoresMalformedLines(t *testing.T) {
	parsed := parseSecretEnvBlob([]byte("NO_EQUALS\nHASP_MASTER_PASSWORD=value\n\n"))
	if parsed["HASP_MASTER_PASSWORD"] != "value" {
		t.Fatalf("parsed master = %q", parsed["HASP_MASTER_PASSWORD"])
	}
	if _, ok := parsed["NO_EQUALS"]; ok {
		t.Fatal("malformed line should be ignored")
	}
}

// TestDaemonSecretGetenvFallsBackToEnv ensures non-daemon callers (no fd loaded)
// still read from the process environment.
func TestDaemonSecretGetenvFallsBackToEnv(t *testing.T) {
	daemonSecretEnvMu.Lock()
	daemonSecretEnv = nil
	daemonSecretEnvMu.Unlock()
	t.Setenv("HASP_MASTER_PASSWORD", "env-value")
	if got := daemonSecretGetenv("HASP_MASTER_PASSWORD"); got != "env-value" {
		t.Fatalf("expected env fallback, got %q", got)
	}
}
