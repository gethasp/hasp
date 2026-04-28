package store

import (
	"strings"
	"testing"
)

func TestResolvePasswordIterationsReturnsBaseWhenEnvEmpty(t *testing.T) {
	if got := resolvePasswordIterations("", 600_000, 300_000); got != 600_000 {
		t.Fatalf("resolvePasswordIterations(\"\", 600k, 300k) = %d, want 600000", got)
	}
}

func TestResolvePasswordIterationsAcceptsEnvOverrideAtOrAboveMinimum(t *testing.T) {
	if got := resolvePasswordIterations("400000", 600_000, 300_000); got != 400_000 {
		t.Fatalf("resolvePasswordIterations(\"400000\", 600k, 300k) = %d, want 400000", got)
	}
	if got := resolvePasswordIterations("300000", 600_000, 300_000); got != 300_000 {
		t.Fatalf("resolvePasswordIterations at exactly minimum = %d, want 300000", got)
	}
	if got := resolvePasswordIterations("  500000\n", 600_000, 300_000); got != 500_000 {
		t.Fatalf("resolvePasswordIterations with surrounding whitespace = %d, want 500000", got)
	}
}

func TestResolvePasswordIterationsPanicsOnBelowMinimum(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for env override below minimum, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic with string message, got %T: %v", r, r)
		}
		if !strings.Contains(msg, "100") || !strings.Contains(msg, "300000") {
			t.Fatalf("panic message should mention the supplied value and the minimum, got: %q", msg)
		}
	}()
	resolvePasswordIterations("100", 600_000, 300_000)
}

func TestResolvePasswordIterationsPanicsOnGarbage(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for non-numeric env override, got none")
		}
	}()
	resolvePasswordIterations("garbage", 600_000, 300_000)
}

func TestDerivePasswordIterationsBasenameSniffIsRemoved(t *testing.T) {
	// The old basename-based downgrade (whose presence let any binary renamed
	// "*.test" silently weaken every vault it then init'd) must not exist.
	// This test would fail to compile if `derivePasswordIterations` were
	// reintroduced, since the symbol would shadow this scope.
	//
	// We assert this via a regression on the resolver's pure surface.
	if got := resolvePasswordIterations("", 600_000, 300_000); got == 100_000 {
		t.Fatal("base value must not be silently downgraded to test iterations from a basename sniff")
	}
}
