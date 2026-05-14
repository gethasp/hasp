package release

import (
	"errors"
	"strings"
	"testing"
)

func TestParseSemVerAccepts(t *testing.T) {
	cases := []struct {
		in   string
		want SemVer
	}{
		{"1.2.3", SemVer{1, 2, 3, ""}},
		{"v1.2.3", SemVer{1, 2, 3, ""}},
		{"v1.0.0", SemVer{1, 0, 0, ""}},
		{"1.2.3-rc.1", SemVer{1, 2, 3, "rc.1"}},
		{"1.2.3+meta", SemVer{1, 2, 3, ""}},
		{"1.2.3-beta+go", SemVer{1, 2, 3, "beta"}},
		{" v1.0.10+build.7 ", SemVer{1, 0, 10, ""}},
	}
	for _, c := range cases {
		got, err := ParseSemVer(c.in)
		if err != nil {
			t.Fatalf("ParseSemVer(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseSemVer(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseSemVerRejects(t *testing.T) {
	for _, in := range []string{"", "1.2", "1.2.3.4", "a.b.c", "1.2.x", "-1.2.3"} {
		if _, err := ParseSemVer(in); !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("ParseSemVer(%q): expected ErrInvalidVersion, got %v", in, err)
		}
	}
}

func TestSemVerCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.1.0", "1.2.0", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
	}
	for _, c := range cases {
		a, _ := ParseSemVer(c.a)
		b, _ := ParseSemVer(c.b)
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s vs %s: got %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSemVerStringOmitsEmptyPrerelease(t *testing.T) {
	if got := (SemVer{Major: 1, Minor: 0, Patch: 9}).String(); got != "1.0.9" {
		t.Fatalf("stable String() = %q, want 1.0.9", got)
	}
	if got := (SemVer{Major: 1, Minor: 0, Patch: 9, Prerelease: "rc.1"}).String(); got != "1.0.9-rc.1" {
		t.Fatalf("prerelease String() = %q, want 1.0.9-rc.1", got)
	}
}

func TestCheckUpgradeRefusesSameAndOlder(t *testing.T) {
	if err := CheckUpgrade("1.0.0", "1.0.0"); !errors.Is(err, ErrDowngrade) {
		t.Errorf("same version: expected ErrDowngrade, got %v", err)
	}
	if err := CheckUpgrade("1.1.0", "1.0.0"); !errors.Is(err, ErrDowngrade) {
		t.Errorf("older target: expected ErrDowngrade, got %v", err)
	}
	if err := CheckUpgrade("1.0.0", "1.0.0-rc.1"); !errors.Is(err, ErrDowngrade) {
		t.Errorf("prerelease downgrade: expected ErrDowngrade, got %v", err)
	}
}

func TestCheckUpgradeAcceptsForward(t *testing.T) {
	for _, c := range [][2]string{
		{"1.0.0", "1.1.0"},
		{"1.0.0", "2.0.0"},
		{"1.0.0-rc.1", "1.0.0"},
	} {
		if err := CheckUpgrade(c[0], c[1]); err != nil {
			t.Errorf("CheckUpgrade(%s, %s): %v", c[0], c[1], err)
		}
	}
}

func TestCheckUpgradeRejectsBadInput(t *testing.T) {
	if err := CheckUpgrade("not-a-version", "1.0.0"); err == nil || !strings.Contains(err.Error(), "current version") {
		t.Errorf("bad current: %v", err)
	}
	if err := CheckUpgrade("1.0.0", "garbage"); err == nil || !strings.Contains(err.Error(), "target version") {
		t.Errorf("bad target: %v", err)
	}
}
