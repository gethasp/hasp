package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSetupVerifyConvenienceUnlockWithRetryBranches(t *testing.T) {
	lockAppSeams(t)

	origVerify := setupVerifyConvenienceUnlockFn
	origRetries := setupConvenienceVerifyRetries
	origDelay := setupConvenienceRetryDelay
	origSleep := setupSleepFn
	defer func() {
		setupVerifyConvenienceUnlockFn = origVerify
		setupConvenienceVerifyRetries = origRetries
		setupConvenienceRetryDelay = origDelay
		setupSleepFn = origSleep
	}()

	setupConvenienceVerifyRetries = 0
	verifyCalls := 0
	setupVerifyConvenienceUnlockFn = func(context.Context, *store.Store) error {
		verifyCalls++
		return nil
	}
	if err := setupVerifyConvenienceUnlockWithRetry(context.Background(), nil); err != nil {
		t.Fatalf("expected single-attempt success when retries <= 0, got %v", err)
	}
	if verifyCalls != 1 {
		t.Fatalf("expected one verify call, got %d", verifyCalls)
	}

	setupConvenienceVerifyRetries = 3
	verifyCalls = 0
	sleepCalls := 0
	setupSleepFn = func(time.Duration) { sleepCalls++ }
	setupVerifyConvenienceUnlockFn = func(context.Context, *store.Store) error {
		verifyCalls++
		if verifyCalls < 2 {
			return fmt.Errorf("%w: transient", store.ErrKeyringUnavailable)
		}
		return nil
	}
	if err := setupVerifyConvenienceUnlockWithRetry(context.Background(), nil); err != nil {
		t.Fatalf("expected retry success, got %v", err)
	}
	if verifyCalls != 2 || sleepCalls != 1 {
		t.Fatalf("expected retry path with one sleep, got verifyCalls=%d sleepCalls=%d", verifyCalls, sleepCalls)
	}

	verifyCalls = 0
	setupVerifyConvenienceUnlockFn = func(context.Context, *store.Store) error {
		verifyCalls++
		return errors.New("verify fail")
	}
	if err := setupVerifyConvenienceUnlockWithRetry(context.Background(), nil); err == nil || err.Error() != "verify fail" {
		t.Fatalf("expected immediate generic failure, got %v", err)
	}
	if verifyCalls != 1 {
		t.Fatalf("expected no retry for generic failure, got %d calls", verifyCalls)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	setupVerifyConvenienceUnlockFn = func(context.Context, *store.Store) error { return store.ErrKeyringUnavailable }
	if err := setupVerifyConvenienceUnlockWithRetry(canceled, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled context, got %v", err)
	}
}

func TestSetupConvenienceUnlockDetailAndSummary(t *testing.T) {
	if got := setupConvenienceUnlockDetail(nil); got != "" {
		t.Fatalf("expected empty detail for nil error, got %q", got)
	}
	if got := setupConvenienceUnlockDetail(errors.New("")); got != "" {
		t.Fatalf("expected empty detail for blank error, got %q", got)
	}
	if got := setupConvenienceUnlockDetail(store.ErrKeyringUnavailable); got != "macOS keychain access did not complete during setup" {
		t.Fatalf("unexpected bare unavailable detail %q", got)
	}
	if got := setupConvenienceUnlockDetail(fmt.Errorf("%w: keychain write failed: denied", store.ErrKeyringUnavailable)); got != "keychain write failed: denied" {
		t.Fatalf("unexpected wrapped unavailable detail %q", got)
	}
	if got := setupConvenienceUnlockDetail(context.DeadlineExceeded); got != "macOS keychain access did not complete during setup" {
		t.Fatalf("unexpected deadline detail %q", got)
	}
	if got := setupConvenienceUnlockDetail(errors.New("plain failure")); got != "plain failure" {
		t.Fatalf("unexpected plain detail %q", got)
	}

	steps := setupNextSteps("", store.Binding{}, "/tmp/hasp-home", "unavailable", "keychain write failed: denied", true, true)
	if !strings.Contains(strings.Join(steps, "\n"), "unlock your macOS login keychain") {
		t.Fatalf("expected convenience guidance in next steps, got %+v", steps)
	}
	notes := setupNotes([]setupAgentSpec{{ID: "codex-cli"}}, false, setupOptions{}, "unavailable", "keychain write failed: denied")
	if !strings.Contains(strings.Join(notes, "\n"), "convenience unlock detail: keychain write failed: denied") {
		t.Fatalf("expected convenience detail note, got %+v", notes)
	}

	var out bytes.Buffer
	if err := renderSetupSummary(&out, setupSummary{
		HaspHome:          "/tmp/hasp-home",
		ConfigPath:        "/tmp/config.json",
		InitState:         "created",
		AutoProtectRepos:  true,
		AutoInstallHooks:  true,
		ConvenienceUnlock: "unavailable",
		ConvenienceDetail: "keychain write failed: denied",
		Notes:             []string{"note"},
		NextSteps:         []string{"step"},
		Verification:      map[string]any{},
	}); err != nil {
		t.Fatalf("render setup summary: %v", err)
	}
	if !strings.Contains(out.String(), "Convenience detail") || !strings.Contains(out.String(), "keychain write failed: denied") {
		t.Fatalf("expected convenience detail in summary, got %q", out.String())
	}
}

func TestSetupConvenienceUnlockUnavailableHelper(t *testing.T) {
	if !setupConvenienceUnlockUnavailable(store.ErrKeyringUnavailable) {
		t.Fatal("expected keyring unavailable to count")
	}
	if !setupConvenienceUnlockUnavailable(context.DeadlineExceeded) {
		t.Fatal("expected deadline exceeded to count")
	}
	if setupConvenienceUnlockUnavailable(io.EOF) {
		t.Fatal("did not expect arbitrary error to count")
	}
}
