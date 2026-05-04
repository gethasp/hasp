package release

import (
	"errors"
	"strings"
	"testing"
)

func TestParseSemVerAccepts(t *testing.T) {
	cases := map[string]SemVer{
		"1.2.3":         {1, 2, 3, ""},
		"v1.2.3":        {1, 2, 3, ""},
		"v1.0.0":        {1, 0, 0, ""},
		"1.2.3-rc.1":    {1, 2, 3, "rc.1"},
		"1.2.3+meta":    {1, 2, 3, ""},
		"1.2.3-beta+go": {1, 2, 3, "beta"},
	}
	for in, want := range cases {
		got, err := ParseSemVer(in)
		if err != nil {
			t.Fatalf("ParseSemVer(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("ParseSemVer(%q) = %+v, want %+v", in, got, want)
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
