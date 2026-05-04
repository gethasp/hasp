package store

// RED tests for hasp-9922 — `Handle.RekeyPassword` rotates the master
// password without touching the underlying vault key, so all sealed-under-
// DEK material survives. Contract pinned:
//
//   - Wrong old password → ErrInvalidPassword (fail-closed; no oracle).
//   - After rekey, the OLD password no longer unlocks the vault.
//   - After rekey, the NEW password unlocks the vault and items are intact.
//   - Rekey clears any active ConvenienceWrap (per the bead) so that a
//     stolen device-key replay cannot resurrect the rotated password.
//   - Rekey writes an audit event of type `EventRekey` with no values.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

func TestRekeyPasswordRotatesUnlockToNewPassword(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "old-password"); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "old-password")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := handle.UpsertItem("API_TOKEN", ItemKindKV, []byte("supersecret"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := handle.RekeyPassword(context.Background(), "old-password", "new-password"); err != nil {
		t.Fatalf("RekeyPassword: %v", err)
	}

	if _, err := store.OpenWithPassword(context.Background(), "old-password"); err == nil {
		t.Fatal("expected old password to fail after rekey")
	}
	reopened, err := store.OpenWithPassword(context.Background(), "new-password")
	if err != nil {
		t.Fatalf("reopen with new password: %v", err)
	}
	got, err := reopened.GetItem("API_TOKEN")
	if err != nil {
		t.Fatalf("get item after rekey: %v", err)
	}
	if string(got.Value) != "supersecret" {
		t.Fatalf("item value lost across rekey: %q", got.Value)
	}
}

func TestRekeyPasswordRejectsWrongOldPassword(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "old-password"); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "old-password")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	err = handle.RekeyPassword(context.Background(), "wrong-old", "new-password")
	if err == nil {
		t.Fatal("expected wrong old password to be rejected")
	}
	// Old password must still work after the rejected rekey attempt.
	if _, err := store.OpenWithPassword(context.Background(), "old-password"); err != nil {
		t.Fatalf("old password no longer unlocks after rejected rekey: %v", err)
	}
}

func TestRekeyPasswordRejectsEmptyNewPassword(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "old-password"); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "old-password")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := handle.RekeyPassword(context.Background(), "old-password", ""); err == nil {
		t.Fatal("expected empty new password to be rejected")
	}
	if err := handle.RekeyPassword(context.Background(), "old-password", "   "); err == nil {
		t.Fatal("expected whitespace new password to be rejected")
	}
}

func TestRekeyPasswordClearsConvenienceWrap(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStoreWithKeyring(t, newMemoryKeyring())
	if err := store.Init(context.Background(), "old-password"); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "old-password")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience: %v", err)
	}
	pre, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("pre read: %v", err)
	}
	if pre.Header.ConvenienceWrap == nil {
		t.Fatal("setup: expected ConvenienceWrap to be present")
	}

	if err := handle.RekeyPassword(context.Background(), "old-password", "new-password"); err != nil {
		t.Fatalf("RekeyPassword: %v", err)
	}

	post, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("post read: %v", err)
	}
	if post.Header.ConvenienceWrap != nil {
		t.Fatal("expected ConvenienceWrap to be cleared after rekey")
	}
}

func TestRekeyPasswordWritesAuditEventWithoutValues(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "old-password"); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "old-password")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if err := handle.RekeyPassword(context.Background(), "old-password", "new-password"); err != nil {
		t.Fatalf("RekeyPassword: %v", err)
	}

	events, err := store.audit.Events()
	if err != nil {
		t.Fatalf("audit events: %v", err)
	}
	saw := false
	for _, ev := range events {
		if ev.Type != audit.EventRekey {
			continue
		}
		saw = true
		// Defense in depth: neither password may appear anywhere in the
		// event payload — the audit log is plaintext on disk.
		raw, _ := os.ReadFile(store.paths.AuditPath)
		if strings.Contains(string(raw), "old-password") || strings.Contains(string(raw), "new-password") {
			t.Fatalf("audit log leaked a password: %s", string(raw))
		}
	}
	if !saw {
		t.Fatal("expected an audit event of type EventRekey")
	}
}
