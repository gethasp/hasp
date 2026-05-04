package app

// Red-team tests for hasp-x05.1.3 (unit portion): Onboarding usability bar.
// These tests assert that a named usability bar exists as a function or
// constant in the app package, returning a struct with MaxSeconds <= 120 and
// Steps >= 1.  They must fail until the green team creates SetupUsabilityBar.

import (
	"testing"
)

// TestSetupUsabilityBarExists asserts that the package exposes a function or
// value named SetupUsabilityBar (or setupUsabilityBar) that returns a struct
// (or map) with at least:
//   - MaxSeconds: numeric, <= 120
//   - Steps: numeric, >= 1
//
// The current code has no such symbol, so this test will fail to compile or
// fail at runtime.
func TestSetupUsabilityBarExists(t *testing.T) {
	bar := setupUsabilityBar()

	if bar.MaxSeconds <= 0 {
		t.Fatalf("expected SetupUsabilityBar.MaxSeconds > 0, got %d", bar.MaxSeconds)
	}
	if bar.MaxSeconds > 120 {
		t.Fatalf("expected SetupUsabilityBar.MaxSeconds <= 120 (usability budget), got %d", bar.MaxSeconds)
	}
	if bar.Steps < 1 {
		t.Fatalf("expected SetupUsabilityBar.Steps >= 1, got %d", bar.Steps)
	}
}

// TestSetupUsabilityBarIsNotZeroValue guards against a trivially passing
// zero-value struct.
func TestSetupUsabilityBarIsNotZeroValue(t *testing.T) {
	bar := setupUsabilityBar()
	if bar.MaxSeconds == 0 && bar.Steps == 0 {
		t.Fatalf("setupUsabilityBar() returned zero value — must be explicitly configured")
	}
}
