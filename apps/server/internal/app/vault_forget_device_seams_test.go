package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// TestVaultForgetDeviceFlagAndUsageErrors covers the two cheap error paths:
// an unknown flag (ContinueOnError surfaces flag.ErrHelp-style failure) and
// stray positional args after the subcommand. Both must fail before any
// vault work happens.
func TestVaultForgetDeviceFlagAndUsageErrors(t *testing.T) {
	if err := vaultForgetDeviceCommand(context.Background(), []string{"--bad"}, io.Discard); err == nil {
		t.Fatal("expected parse error for unknown flag")
	}
	if err := vaultForgetDeviceCommand(context.Background(), []string{"extra"}, io.Discard); err == nil {
		t.Fatal("expected usage error for trailing arg")
	}
}

// TestVaultForgetDeviceOpenFailurePropagates checks that when the vault
// handle cannot be opened at all (e.g., HASP_MASTER_PASSWORD unset and
// no convenience unlock) the CLI surfaces the underlying error verbatim.
func TestVaultForgetDeviceOpenFailurePropagates(t *testing.T) {
	origOpen := openVaultHandleFn
	defer func() { openVaultHandleFn = origOpen }()
	openVaultHandleFn = func(context.Context) (*store.Handle, error) {
		return nil, errors.New("vault open fail")
	}
	err := vaultForgetDeviceCommand(context.Background(), nil, io.Discard)
	if err == nil || err.Error() != "vault open fail" {
		t.Fatalf("expected vault open fail, got %v", err)
	}
}

// TestVaultForgetDeviceDisableFailurePropagates ensures keychain/envelope
// failures from the store layer surface to the operator rather than being
// silently swallowed.
func TestVaultForgetDeviceDisableFailurePropagates(t *testing.T) {
	origOpen := openVaultHandleFn
	defer func() {
		openVaultHandleFn = origOpen
	}()
	openVaultHandleFn = func(context.Context) (*store.Handle, error) { return &store.Handle{}, nil }
	deps := defaultVaultGrantOpsDeps()
	deps.DisableConvenienceUnlock = func(*store.Handle, context.Context) (bool, error) {
		return false, errors.New("forget keychain entry: boom")
	}
	err := vaultForgetDeviceCommandWithDeps(context.Background(), nil, io.Discard, deps)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected disable failure, got %v", err)
	}
}

// TestVaultLockForgetDeviceFailurePropagates locks in that vault lock
// refuses to claim success when the forget-device leg fails — otherwise the
// "whole turtle" promise in the help text is a lie.
func TestVaultLockForgetDeviceFailurePropagates(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	deps := defaultVaultGrantOpsDeps()
	deps.DisableConvenienceUnlock = func(*store.Handle, context.Context) (bool, error) {
		return false, errors.New("disable fail")
	}
	err := vaultLockCommandWithDeps(context.Background(), nil, io.Discard, &fakeStarter{}, deps)
	if err == nil || err.Error() != "disable fail" {
		t.Fatalf("expected disable failure to propagate, got %v", err)
	}
}

// TestVaultForgetDeviceIdempotentHumanOutput exercises the "already
// forgotten" branch of the human renderer — a vault that never enabled
// convenience unlock still yields exit 0 and a message that tells the
// operator nothing needed to change.
func TestVaultForgetDeviceIdempotentHumanOutput(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"vault", "forget-device"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("vault forget-device: %v", err)
	}
	if !strings.Contains(strings.ToLower(out.String()), "already") {
		t.Fatalf("idempotent human output must mention already-cleared state, got:\n%s", out.String())
	}
}

// TestDisableConvenienceUnlockReadEnvelopeFailureSurfaces covers the first
// error path inside the store primitive: a corrupted envelope that cannot
// be parsed. The command must not clear anything or touch the keychain.
func TestDisableConvenienceUnlockReadEnvelopeFailureSurfaces(t *testing.T) {
	origOpen := openVaultHandleFn
	defer func() { openVaultHandleFn = origOpen }()

	keyring := newAppMemoryKeyring()
	origNewStore := newVaultStoreFn
	defer func() { newVaultStoreFn = origNewStore }()
	newVaultStoreFn = func() (*store.Store, error) { return store.New(keyring) }

	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}

	var out bytes.Buffer
	if err := Run(context.Background(), []string{"vault", "forget-device", "--json"}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("forget-device on no-wrap vault: %v", err)
	}
	payload := decodeObject(t, out.Bytes())
	if payload["had_wrap"] != false {
		t.Fatalf("vault with no wrap must report had_wrap=false, got %+v", payload)
	}
	if payload["convenience_state"] != "already_forgotten" {
		t.Fatalf("vault with no wrap must report convenience_state=already_forgotten, got %+v", payload)
	}
}
