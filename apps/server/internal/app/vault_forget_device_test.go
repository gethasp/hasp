package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// enableConvenienceViaMemoryKeyring wires the app's vault-store seam to a
// process-local memory keyring, initializes a vault in HASP_HOME, and enables
// convenience unlock against it — so the CLI under test can exercise the
// full forget-device path without poking the real macOS/Linux keychain.
func enableConvenienceViaMemoryKeyring(t *testing.T) *appMemoryKeyring {
	t.Helper()
	keyring := newAppMemoryKeyring()
	origNewStore := newVaultStoreFn
	t.Cleanup(func() { newVaultStoreFn = origNewStore })
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }

	const password = "correct horse battery staple"
	t.Setenv("HASP_MASTER_PASSWORD", password)
	vaultStore, err := store.New(keyring)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), password); err != nil && !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := vaultStore.OpenWithPassword(context.Background(), password)
	if err != nil {
		t.Fatalf("open with password: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}
	return keyring
}

// TestVaultForgetDeviceClearsConvenienceAndPrintsResult drives the end-to-end
// CLI surface: `hasp vault forget-device` must open the vault, call the
// store's DisableConvenienceUnlock, and render either JSON or the familiar
// human "Key/Value" block. The contract we lock in:
//   - first invocation after EnableConvenienceUnlock reports "forgotten"
//     (had_wrap=true in JSON) so the operator sees real work happened;
//   - second invocation is idempotent: exits 0 and reports had_wrap=false.
func TestVaultForgetDeviceClearsConvenienceAndPrintsResult(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	keyring := enableConvenienceViaMemoryKeyring(t)

	var out bytes.Buffer
	if err := Run(context.Background(), []string{"vault", "forget-device", "--json"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("vault forget-device --json: %v", err)
	}
	payload := decodeObject(t, out.Bytes())
	if payload["had_wrap"] != true {
		t.Fatalf("first vault forget-device must report had_wrap=true, got %+v", payload)
	}
	if payload["convenience_state"] != "forgotten" {
		t.Fatalf("first vault forget-device must report convenience_state=forgotten, got %+v", payload)
	}
	if len(keyring.values) != 0 {
		t.Fatalf("keychain entry must be deleted; still have %+v", keyring.values)
	}

	out.Reset()
	if err := Run(context.Background(), []string{"vault", "forget-device", "--json"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("second vault forget-device --json: %v", err)
	}
	payload = decodeObject(t, out.Bytes())
	if payload["had_wrap"] != false {
		t.Fatalf("idempotent vault forget-device must report had_wrap=false, got %+v", payload)
	}
}

// TestVaultForgetDeviceHumanOutput locks in the operator-facing text so the
// human path is not silently JSON-only.
func TestVaultForgetDeviceHumanOutput(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	enableConvenienceViaMemoryKeyring(t)

	var out bytes.Buffer
	if err := Run(context.Background(), []string{"vault", "forget-device"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("vault forget-device: %v", err)
	}
	body := out.String()
	if !strings.Contains(strings.ToLower(body), "convenience") {
		t.Fatalf("human output must mention convenience, got:\n%s", body)
	}
}

// TestVaultLockAlsoForgetsDevice locks in the renamed semantics from the
// adversarial review: `hasp vault lock` must now do BOTH revoke-all-sessions
// AND forget-device, so an operator who types "lock" after walking away from
// the machine gets the whole turtle — no live convenience wrap, no in-memory
// grants, no open daemon sessions. The lock output must reflect that the
// convenience wrap was cleared when there was one.
func TestVaultLockAlsoForgetsDevice(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	keyring := enableConvenienceViaMemoryKeyring(t)

	var out bytes.Buffer
	if err := Run(context.Background(), []string{"vault", "lock", "--json"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("vault lock --json: %v", err)
	}
	payload := decodeObject(t, out.Bytes())
	if payload["vault_state"] != "locked" {
		t.Fatalf("vault lock must report vault_state=locked, got %+v", payload)
	}
	if payload["convenience_state"] != "forgotten" {
		t.Fatalf("vault lock must also forget device (convenience_state=forgotten), got %+v", payload)
	}
	if len(keyring.values) != 0 {
		t.Fatalf("vault lock must also delete keychain entry; still have %+v", keyring.values)
	}
}

// TestVaultForgetDeviceHelpIsReachable checks the help surface lists the new
// subcommand so users discover it without having to read source.
func TestVaultForgetDeviceHelpIsReachable(t *testing.T) {
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"help", "vault"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("help vault: %v", err)
	}
	if !strings.Contains(out.String(), "forget-device") {
		t.Fatalf("help vault must list forget-device subcommand, got:\n%s", out.String())
	}
}

// TestVaultForgetDeviceHelpTopicRendersDetailedText ensures `hasp help vault
// forget-device` works as a standalone topic (matches the other vault help
// surfaces) and explains the two-effect operation so operators understand
// why it is a security-meaningful action, not a cosmetic clear-cache.
func TestVaultForgetDeviceHelpTopicRendersDetailedText(t *testing.T) {
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"help", "vault", "forget-device"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("help vault forget-device: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, "keychain") || !strings.Contains(body, "convenience") {
		t.Fatalf("help vault forget-device must document keychain + convenience wrap effects, got:\n%s", body)
	}
}
