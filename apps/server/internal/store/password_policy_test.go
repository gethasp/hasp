package store

import (
	"strings"
	"testing"
)

// hasp-wlkm: validateMasterPassword historically only rejected the empty
// string, which lets users pin a vault to a 4-character password. The
// review punch list calls for a length/entropy floor with a documented
// escape hatch. EnforcePasswordPolicy is the externally-callable check
// that bootstrap and setup wire in before Init; tests pin its contract
// so future changes can't silently weaken the floor.

func TestEnforcePasswordPolicyRejectsShortPasswords(t *testing.T) {
	cases := []string{"", "a", "1234567", "  short  "}
	for _, pw := range cases {
		if err := EnforcePasswordPolicy(pw); err == nil {
			t.Fatalf("expected EnforcePasswordPolicy(%q) to fail; got nil", pw)
		}
	}
}

func TestEnforcePasswordPolicyAcceptsStrong(t *testing.T) {
	cases := []string{
		"correct horse battery staple",
		"hunter2hunter2",
		strings.Repeat("a", 6) + strings.Repeat("b", 6) + "1",
	}
	for _, pw := range cases {
		if err := EnforcePasswordPolicy(pw); err != nil {
			t.Fatalf("EnforcePasswordPolicy(%q) unexpected error: %v", pw, err)
		}
	}
}

func TestEnforcePasswordPolicyRejectsRepeatedChars(t *testing.T) {
	if err := EnforcePasswordPolicy(strings.Repeat("a", 24)); err == nil {
		t.Fatal("expected uniform-character password to fail policy check")
	}
}

func TestEnforcePasswordPolicyMessageContainsMinimum(t *testing.T) {
	err := EnforcePasswordPolicy("abc")
	if err == nil {
		t.Fatal("expected short password to fail")
	}
	if !strings.Contains(err.Error(), "12") {
		t.Fatalf("expected error to surface minimum length; got %q", err.Error())
	}
}
