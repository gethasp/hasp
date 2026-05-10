package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/auditops"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// TestAuditHMACKeyCacheLifecycle exercises the process-level audit-key cache
// (set/get/clear) directly so its branches are covered without standing up a
// full vault: empty input clears, the get path returns a defensive copy,
// clear empties the slot.
func TestAuditHMACKeyCacheLifecycle(t *testing.T) {
	lockAppSeams(t)

	if got := getAuditHMACKey(); got != nil {
		t.Fatalf("expected nil key after lockAppSeams clear, got %d bytes", len(got))
	}

	original := []byte("0123456789abcdef0123456789abcdef")
	setAuditHMACKey(original)
	got := getAuditHMACKey()
	if !bytes.Equal(got, original) {
		t.Fatalf("expected key roundtrip, got %x", got)
	}
	// Mutating the returned copy must not affect the cached key.
	got[0] ^= 0xff
	if again := getAuditHMACKey(); !bytes.Equal(again, original) {
		t.Fatalf("get returned a non-defensive copy: cache mutated")
	}

	// Empty input clears the slot.
	setAuditHMACKey(nil)
	if got := getAuditHMACKey(); got != nil {
		t.Fatalf("expected nil after setAuditHMACKey(nil), got %d bytes", len(got))
	}

	setAuditHMACKey([]byte("seed"))
	clearAuditHMACKey()
	if got := getAuditHMACKey(); got != nil {
		t.Fatalf("expected nil after clearAuditHMACKey, got %d bytes", len(got))
	}
}

// TestHandleAuditHMACKeyNilSafety covers the nil-receiver and empty-vault-key
// guard so a caller that holds an unopened Handle never panics.
func TestHandleAuditHMACKeyNilSafety(t *testing.T) {
	lockAppSeams(t)
	var h *store.Handle
	if got := h.AuditHMACKey(); got != nil {
		t.Fatalf("expected nil from nil receiver, got %d bytes", len(got))
	}
}

// TestAuditVerifySubcommandAlias exercises the `hasp audit verify` form: it
// must produce the same JSON `{"status":"ok","chain":"verified"}` payload as
// `hasp audit --verify` and must reject any extra positional arg.
func TestAuditVerifySubcommandAlias(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Subcommand alias.
	var aliasOut bytes.Buffer
	if err := Run(context.Background(), []string{"audit", "verify", "--json"}, bytes.NewBuffer(nil), &aliasOut, &aliasOut); err != nil {
		t.Fatalf("audit verify: %v", err)
	}
	var aliasPayload map[string]any
	if err := json.Unmarshal(aliasOut.Bytes(), &aliasPayload); err != nil {
		t.Fatalf("decode alias payload: %v\nraw: %s", err, aliasOut.String())
	}
	if aliasPayload["status"] != "ok" || aliasPayload["chain"] != "verified" {
		t.Fatalf("unexpected alias payload: %v", aliasPayload)
	}

	// Equivalent --verify flag.
	var flagOut bytes.Buffer
	if err := Run(context.Background(), []string{"audit", "--verify", "--json"}, bytes.NewBuffer(nil), &flagOut, &flagOut); err != nil {
		t.Fatalf("audit --verify: %v", err)
	}
	var flagPayload map[string]any
	if err := json.Unmarshal(flagOut.Bytes(), &flagPayload); err != nil {
		t.Fatalf("decode flag payload: %v\nraw: %s", err, flagOut.String())
	}
	if flagPayload["status"] != "ok" || flagPayload["chain"] != "verified" {
		t.Fatalf("unexpected --verify payload: %v", flagPayload)
	}

	// Extra positional after `verify` still rejected.
	if err := Run(context.Background(), []string{"audit", "verify", "extra"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected error for extra positional after verify")
	}
}

func TestAuditExportNDJSONMatchesSharedDispatcher(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	appendAudit(audit.EventApprove, "daemon", map[string]any{"action": "session.open", "session_id": "s-1"})
	appendAudit(audit.EventDeny, "daemon", map[string]any{"action": "lease.revoke", "lease_id": "l-1"})

	var out bytes.Buffer
	if err := Run(context.Background(), []string{"audit", "export", "--format", "ndjson"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("audit export: %v", err)
	}
	log, err := audit.New()
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	handle, err := openVaultHandleFn(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	log = log.WithKey(handle.AuditHMACKey())
	events, err := log.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	var expected bytes.Buffer
	if _, err := auditops.ExportNDJSON(&expected, events, auditops.ExportOptions{}, log.HMACKey()); err != nil {
		t.Fatalf("expected export: %v", err)
	}
	if !bytes.Equal(out.Bytes(), expected.Bytes()) {
		t.Fatalf("audit export mismatch\ngot=%s\nwant=%s", out.Bytes(), expected.Bytes())
	}
}

// TestAuditVerifyHumanReadable exercises the human-readable rendering branch
// of --verify so the renderer is not skipped from coverage.
func TestAuditVerifyHumanReadable(t *testing.T) {
	lockAppSeams(t)

	origLog := newAuditLogFn
	defer func() { newAuditLogFn = origLog }()
	// Nil log skips Verify but still hits the verifyMode renderer below.
	newAuditLogFn = func() (*audit.Log, error) { return nil, nil }

	var buf bytes.Buffer
	if err := auditCommandWithArgs(context.Background(), []string{"--verify"}, &buf); err != nil {
		t.Fatalf("--verify human: %v", err)
	}
	if !strings.Contains(buf.String(), "Audit verified") {
		t.Fatalf("expected human-readable confirmation, got %q", buf.String())
	}
}
