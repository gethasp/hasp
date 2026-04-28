package app

// hasp-sc13: secret get for an unknown name must surface E_NOT_FOUND with
// exit-bucket 6, not collapse into the generic E_INTERNAL/exit 1 used by
// vault-locked failures. Scripts have to be able to distinguish these.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestAppErrorExitCodeNotFoundBucket(t *testing.T) {
	got := appErrorExitCode(newAppError(errCodeNotFound, "missing"))
	if got != 6 {
		t.Fatalf("E_NOT_FOUND exit bucket = %d, want 6", got)
	}
	if got == appErrorExitCode(newAppError(errCodeVaultLocked, "")) {
		t.Fatalf("E_NOT_FOUND must not share bucket with E_VAULT_LOCKED")
	}
}

func TestSecretGetUnknownNameReturnsNotFoundEnvelope(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	err := Run(context.Background(), []string{"secret", "show", "DOES_NOT_EXIST"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected secret show on unknown name to fail")
	}
	envelope, ok := err.(*appError)
	if !ok {
		t.Fatalf("expected *appError envelope, got %T: %v", err, err)
	}
	if envelope.Code != errCodeNotFound {
		t.Fatalf("error code = %q, want %q", envelope.Code, errCodeNotFound)
	}
	if !strings.Contains(envelope.Message, "DOES_NOT_EXIST") {
		t.Fatalf("message must echo the missing name: %q", envelope.Message)
	}
	if appErrorExitCode(err) != 6 {
		t.Fatalf("exit code = %d, want 6", appErrorExitCode(err))
	}
}
