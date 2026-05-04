package app

import (
	"context"
	"strings"
	"testing"
)

// hasp-wlkm: bootstrap is one of two vault-creation paths. With the new
// password policy in place, a weak HASP_MASTER_PASSWORD should fail
// closed at the policy gate before vaultStore.Init is reached. The
// --skip-password-policy flag is the documented escape hatch and must
// let the same weak password through to Init.

func TestEnsureBootstrapHandleRejectsWeakPasswordWithoutSkipFlag(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "abc")

	vaultStore, err := newVaultStoreFn()
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	_, _, err = ensureBootstrapHandle(context.Background(), vaultStore, false)
	if err == nil {
		t.Fatal("expected weak password to fail policy check")
	}
	if !strings.Contains(err.Error(), "12 characters") {
		t.Fatalf("expected min-length error, got %v", err)
	}
}

func TestEnsureBootstrapHandleSkipFlagBypassesPolicy(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "abc")

	vaultStore, err := newVaultStoreFn()
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	handle, state, err := ensureBootstrapHandle(context.Background(), vaultStore, true)
	if err != nil {
		t.Fatalf("expected weak password to bypass policy, got %v", err)
	}
	if state != "created" || handle == nil {
		t.Fatalf("unexpected state=%q handle=%v", state, handle)
	}
}
