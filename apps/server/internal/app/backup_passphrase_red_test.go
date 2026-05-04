package app

import (
	"strings"
	"testing"
)

// hasp-su09: when no passphrase source is provided, the error must name the
// env var explicitly so users know which variable to set. Previously said
// only "or the env var".
func TestReadPassphraseNamesEnvVarInRequiredError(t *testing.T) {
	_, err := readPassphrase(false, -1, "", "HASP_BACKUP_PASSPHRASE")
	if err == nil {
		t.Fatal("expected error when no passphrase source supplied")
	}
	if !strings.Contains(err.Error(), "HASP_BACKUP_PASSPHRASE") {
		t.Fatalf("error must name HASP_BACKUP_PASSPHRASE: %v", err)
	}
	if !strings.Contains(err.Error(), "--recovery-passphrase-stdin") {
		t.Fatalf("error must mention --recovery-passphrase-stdin: %v", err)
	}
}

// hasp-su09: ambiguity errors must also name the env var so users can tell
// which inputs are conflicting.
func TestReadPassphraseNamesEnvVarInAmbiguityError(t *testing.T) {
	_, err := readPassphrase(true, -1, "from-env", "HASP_BACKUP_PASSPHRASE")
	if err == nil {
		t.Fatal("expected ambiguity error when stdin and env both set")
	}
	if !strings.Contains(err.Error(), "HASP_BACKUP_PASSPHRASE") {
		t.Fatalf("ambiguity error must name HASP_BACKUP_PASSPHRASE: %v", err)
	}
}
