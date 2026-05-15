package app

import (
	"strings"
	"testing"
)

// hasp-lng7: tri-state bool flags must accept the explicit enum
// always|never|ask. ask leaves the value unset (interactive default), always
// sets value=true, never sets value=false. true/false remain accepted as
// legacy aliases for one release.

func TestSetupOptionalBoolAcceptsAlways(t *testing.T) {
	var b setupOptionalBool
	if err := b.Set("always"); err != nil {
		t.Fatalf("Set(always): %v", err)
	}
	if !b.set || !b.value || b.source != "always" {
		t.Fatalf("always should resolve to set=true, value=true; got %+v", b)
	}
}

func TestSetupOptionalBoolAcceptsNever(t *testing.T) {
	var b setupOptionalBool
	if err := b.Set("never"); err != nil {
		t.Fatalf("Set(never): %v", err)
	}
	if !b.set || b.value || b.source != "never" {
		t.Fatalf("never should resolve to set=true, value=false; got %+v", b)
	}
}

func TestSetupOptionalBoolAcceptsAsk(t *testing.T) {
	var b setupOptionalBool
	if err := b.Set("ask"); err != nil {
		t.Fatalf("Set(ask): %v", err)
	}
	if b.set || b.source != "ask" {
		t.Fatalf("ask should leave the flag unset (interactive default); got %+v", b)
	}
}

func TestSetupOptionalBoolEnumIsCaseInsensitive(t *testing.T) {
	for _, raw := range []string{"ALWAYS", "Always", "  always  "} {
		var b setupOptionalBool
		if err := b.Set(raw); err != nil {
			t.Fatalf("Set(%q): %v", raw, err)
		}
		if !b.set || !b.value {
			t.Fatalf("Set(%q) -> %+v, want set=true value=true", raw, b)
		}
	}
}

func TestSetupOptionalBoolStillAcceptsLegacyTrueFalse(t *testing.T) {
	var b setupOptionalBool
	if err := b.Set("true"); err != nil {
		t.Fatalf("Set(true): %v", err)
	}
	if !b.set || !b.value {
		t.Fatalf("true should still resolve to set=true value=true; got %+v", b)
	}
	var b2 setupOptionalBool
	if err := b2.Set("false"); err != nil {
		t.Fatalf("Set(false): %v", err)
	}
	if !b2.set || b2.value {
		t.Fatalf("false should still resolve to set=true value=false; got %+v", b2)
	}
}

func TestSetupOptionalBoolRejectsUnknownEnum(t *testing.T) {
	var b setupOptionalBool
	err := b.Set("maybe")
	if err == nil {
		t.Fatal("expected error on unknown enum")
	}
	if !strings.Contains(err.Error(), "always|never|ask") {
		t.Fatalf("error should mention always|never|ask vocabulary; got %v", err)
	}
}
