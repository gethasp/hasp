package app

// hasp-th45: bootstrap is a first-class flow and must NOT emit the
// noteSetupCanonical advisory. Only truly-deprecated entry points (hasp init,
// hasp project bind) should redirect users to 'hasp setup'.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// TestNoteSetupCanonicalDoesNotFireOnBootstrap asserts that running
// 'hasp bootstrap' does not print the "hasp setup is the canonical setup
// surface" advisory on stderr. Bootstrap is a first-class flow and the
// advisory is misleading noise there.
func TestNoteSetupCanonicalDoesNotFireOnBootstrap(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	var stderr bytes.Buffer
	// Use 'bootstrap profiles' to pass the early arg-validation bail-out
	// without needing a real profile or network call.
	_ = Run(context.Background(), []string{"bootstrap", "profiles"}, bytes.NewBuffer(nil), io.Discard, &stderr)
	got := stderr.String()
	if strings.Contains(got, "hasp setup") {
		t.Fatalf("bootstrap must not emit the setup advisory, got stderr: %q", got)
	}
}

// TestNoteSetupCanonicalStillFiresOnDeprecatedInit asserts that running
// 'hasp init' still prints the "hasp setup is the canonical setup surface"
// advisory. Init is deprecated in favour of the setup flow.
func TestNoteSetupCanonicalStillFiresOnDeprecatedInit(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	var stderr bytes.Buffer
	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, &stderr); err != nil {
		t.Fatalf("init: %v", err)
	}
	got := stderr.String()
	if !strings.Contains(got, "hasp setup") {
		t.Fatalf("init must still emit the setup advisory, got stderr: %q", got)
	}
}
