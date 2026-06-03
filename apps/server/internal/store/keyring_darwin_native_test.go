//go:build darwin && cgo && !hasp_test_fastkdf

package store

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDarwinKeyringSetNativeRoundTrip verifies the cgo native Set (hasp-4rqu)
// writes to the same default keychain the `security` CLI reads from, with an ACL
// the CLI can read, and with upsert semantics. Uses a throwaway default keychain.
func TestDarwinKeyringSetNativeRoundTrip(t *testing.T) {
	if nativeKeychainSet == nil {
		t.Fatal("nativeKeychainSet must be wired in the cgo build")
	}
	sec := "/usr/bin/security"
	orig, err := exec.Command(sec, "default-keychain").Output()
	if err != nil {
		t.Fatalf("read default keychain: %v", err)
	}
	origPath := strings.Trim(strings.TrimSpace(string(orig)), "\"")

	tmp := filepath.Join(t.TempDir(), "hasp-native.keychain")
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(sec, args...).CombinedOutput(); err != nil {
			t.Fatalf("security %v: %v: %s", args, err, out)
		}
	}
	run("create-keychain", "-p", "", tmp)
	run("unlock-keychain", "-p", "", tmp)
	run("default-keychain", "-s", tmp)
	t.Cleanup(func() {
		_, _ = exec.Command(sec, "default-keychain", "-s", origPath).CombinedOutput()
		_, _ = exec.Command(sec, "delete-keychain", tmp).CombinedOutput()
	})

	kr := DarwinKeyring{}
	const svc, acct = "com.gethasp.hasp.test.native", "tester"
	if err := kr.Set(context.Background(), svc, acct, "round-trip-secret-123"); err != nil {
		t.Fatalf("native Set: %v", err)
	}
	got, err := kr.Get(svc, acct)
	if err != nil {
		t.Fatalf("CLI Get after native Set: %v", err)
	}
	if got != "round-trip-secret-123" {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
	// Upsert: a second Set must overwrite, not duplicate-error.
	if err := kr.Set(context.Background(), svc, acct, "updated-456"); err != nil {
		t.Fatalf("native Set (upsert): %v", err)
	}
	if got, _ := kr.Get(svc, acct); got != "updated-456" {
		t.Fatalf("upsert mismatch: got %q", got)
	}
	if err := kr.Delete(svc, acct); err != nil {
		t.Fatalf("CLI Delete after native Set: %v", err)
	}
}
