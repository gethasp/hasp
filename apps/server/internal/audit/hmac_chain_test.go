package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

// TestAppendWithHMACKeyEmitsKeyedSchemeAndVerifies locks in the GREEN
// behavior: once an HMAC key is installed via WithKey, every appended
// event is stamped with SchemeHMACSHA256V1 and Verify (under the same
// key) walks the chain successfully. A same-UID attacker cannot rewrite
// the line and recompute a passing hash without the key.
func TestAppendWithHMACKeyEmitsKeyedSchemeAndVerifies(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)

	key := []byte("0123456789abcdef0123456789abcdef")
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	log = log.WithKey(key)
	if _, err := log.Append(EventInit, "user", map[string]any{"v": "1.0.0"}); err != nil {
		t.Fatalf("append init: %v", err)
	}
	if _, err := log.Append(EventRun, "user", map[string]any{"cmd": "ls"}); err != nil {
		t.Fatalf("append run: %v", err)
	}

	events, err := log.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	for _, ev := range events {
		if ev.Scheme != SchemeHMACSHA256V1 {
			t.Fatalf("event %d declared scheme %q; want %q", ev.Sequence, ev.Scheme, SchemeHMACSHA256V1)
		}
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("verify under correct key: %v", err)
	}
}

// TestVerifyFailsWhenHMACKeyMissingForKeyedScheme covers the keyForScheme
// fail-closed branch: if a chain contains an HMAC-stamped event but the
// caller didn't install the key (or used the wrong key), Verify must
// surface an error instead of silently accepting tampering.
func TestVerifyFailsWhenHMACKeyMissingForKeyedScheme(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)

	key := []byte("0123456789abcdef0123456789abcdef")
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	log = log.WithKey(key)
	if _, err := log.Append(EventInit, "user", map[string]any{}); err != nil {
		t.Fatalf("append: %v", err)
	}

	verifier, err := New()
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := verifier.Verify(); err == nil || !strings.Contains(err.Error(), "hmac key not installed") {
		t.Fatalf("expected hmac key missing failure, got %v", err)
	}

	wrong := verifier.WithKey([]byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))
	if err := wrong.Verify(); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected hash mismatch under wrong key, got %v", err)
	}
}

// TestVerifyAcceptsMixedLegacyAndKeyedChain locks in the upgrade path:
// an audit log written before the key was wired in (SchemeSHA256 events)
// must continue to verify after the daemon starts stamping new events
// with HMAC. PrevHash chains across the boundary.
func TestVerifyAcceptsMixedLegacyAndKeyedChain(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)

	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	if _, err := log.Append(EventInit, "user", map[string]any{"v": "1.0.1"}); err != nil {
		t.Fatalf("legacy append: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	log = log.WithKey(key)
	if _, err := log.Append(EventRun, "user", map[string]any{"cmd": "upgrade"}); err != nil {
		t.Fatalf("keyed append: %v", err)
	}

	events, err := log.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if events[0].Scheme != SchemeSHA256 {
		t.Fatalf("first event must declare sha256, got %q", events[0].Scheme)
	}
	if events[1].Scheme != SchemeHMACSHA256V1 {
		t.Fatalf("second event must declare hmac scheme, got %q", events[1].Scheme)
	}
	if events[1].PrevHash != events[0].Hash {
		t.Fatalf("chain across schemes broke: prev=%q want=%q", events[1].PrevHash, events[0].Hash)
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("verify mixed chain: %v", err)
	}
}

// TestVerifyRejectsUnknownScheme covers the default branch in
// keyForScheme — a forged event that declares a bogus scheme name to
// dodge verification must not pass.
func TestVerifyRejectsUnknownScheme(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	forged := map[string]any{
		"sequence":  1,
		"timestamp": "2026-04-24T00:00:00Z",
		"type":      "run",
		"prev_hash": "",
		"hash":      "00",
		"scheme":    "made-up",
	}
	data, _ := json.Marshal(forged)
	if err := os.MkdirAll(filepath.Dir(log.path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(log.path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write forged: %v", err)
	}
	if err := log.Verify(); err == nil || !strings.Contains(err.Error(), "unknown audit scheme") {
		t.Fatalf("expected unknown scheme failure, got %v", err)
	}
}

// TestWithKeyClearsKeyWhenEmpty covers the nil/empty branch — after a
// caller (e.g., vault lock) clears the key, subsequent Append calls
// fall back to the legacy SchemeSHA256 path so writes don't fail.
func TestWithKeyClearsKeyWhenEmpty(t *testing.T) {
	home := t.TempDir()
	t.Setenv(paths.EnvHome, home)
	log, err := New()
	if err != nil {
		t.Fatalf("new audit log: %v", err)
	}
	log = log.WithKey([]byte("0123456789abcdef0123456789abcdef")).WithKey(nil)
	if log.key != nil {
		t.Fatalf("WithKey(nil) must clear; got %x", log.key)
	}
	if _, err := log.Append(EventRun, "user", nil); err != nil {
		t.Fatalf("append with cleared key: %v", err)
	}
	events, err := log.Events()
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if events[0].Scheme != SchemeSHA256 {
		t.Fatalf("cleared-key append must declare sha256, got %q", events[0].Scheme)
	}
}

// TestWithKeyHandlesNilReceiver guards the public API: callers that hand
// out a (*Log)(nil) should not panic when trying to install a key.
func TestWithKeyHandlesNilReceiver(t *testing.T) {
	var log *Log
	if got := log.WithKey([]byte("k")); got != nil {
		t.Fatalf("WithKey on nil receiver must return nil, got %p", got)
	}
}
