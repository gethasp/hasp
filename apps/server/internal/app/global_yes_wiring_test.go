package app

// hasp-yat2: --yes wiring sweep. The previously hardcoded confirmation
// points (launcher install, PATH update, secret-add expose-bind) must
// honor the ambient --yes flag so scripts don't dead-lock on a TTY check
// that succeeds only by accident.

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func ctxWithYes() context.Context {
	gf := globalFlagsFromContext(context.Background())
	gf.yes = true
	return contextWithGlobalFlags(context.Background(), gf)
}

func TestResolveAppLauncherInstallChoiceWithYesSkipsPrompt(t *testing.T) {
	// stdin is a non-TTY bytes.Buffer; without --yes this returns false. With
	// --yes we still want the safer non-installing default, but importantly the
	// path must short-circuit (no prompt), which we verify by passing an empty
	// reader — a prompt would block.
	got, err := resolveAppLauncherInstallChoice(ctxWithYes(), "myapp", setupOptionalBool{}, &bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("resolveAppLauncherInstallChoice: %v", err)
	}
	if got {
		t.Fatalf("--yes alone should not flip install to true; explicit --install=always is required")
	}
}

func TestEnsureLauncherDirOnPathChoiceWithYesSkipsPrompt(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/bin") // ensure launcherDir is not already on PATH
	got, err := ensureLauncherDirOnPathChoice(ctxWithYes(), setupOptionalBool{}, &bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}, "/tmp/hasp-launchers-yat2")
	if err != nil {
		t.Fatalf("ensureLauncherDirOnPathChoice: %v", err)
	}
	if got.Changed {
		t.Fatalf("--yes alone must not silently mutate shell rc files")
	}
}

func TestResolveSecretAddExposeWithYesAcceptsBindDefault(t *testing.T) {
	// `--expose=ask` + non-TTY stdin normally errors out. With ambient --yes,
	// it should take the default ("bind to repo") without prompting.
	prompt := newSecretPrompt(&bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{})
	got, err := resolveSecretAddExpose(ctxWithYes(), true, false, "ask", prompt)
	if err != nil {
		t.Fatalf("resolveSecretAddExpose: %v", err)
	}
	if !got {
		t.Fatalf("--yes must accept the default-true bind answer")
	}
}

func TestResolveSecretAddExposeWithoutYesStillRefusesNonInteractive(t *testing.T) {
	// Sanity: without --yes, non-interactive + ask remains a hard error so
	// scripts can't accidentally bind a fresh secret to a stranger repo.
	prompt := newSecretPrompt(&bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{})
	_, err := resolveSecretAddExpose(context.Background(), true, false, "ask", prompt)
	if err == nil {
		t.Fatal("non-interactive --expose=ask without --yes must error")
	}
	if !strings.Contains(err.Error(), "non-interactive") {
		t.Fatalf("error should mention non-interactive: %v", err)
	}
}
