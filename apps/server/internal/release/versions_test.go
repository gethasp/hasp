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
		{" v1.0.11+build.7 ", SemVer{1, 0, 11, ""}},
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

func TestComparePrereleaseCoverageEdges(t *testing.T) {
	cases := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{name: "numeric less", a: "rc.1", b: "rc.2", want: -1},
		{name: "numeric greater", a: "rc.10", b: "rc.2", want: 1},
		{name: "numeric before alpha", a: "1", b: "alpha", want: -1},
		{name: "alpha after numeric", a: "alpha", b: "1", want: 1},
		{name: "alpha compare", a: "beta", b: "alpha", want: 1},
		{name: "shorter segments", a: "alpha", b: "alpha.1", want: -1},
		{name: "longer segments", a: "alpha.1", b: "alpha", want: 1},
		{name: "equal", a: "alpha.1", b: "alpha.1", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := comparePrerelease(tc.a, tc.b)
			switch {
			case tc.want < 0 && got >= 0:
				t.Fatalf("comparePrerelease(%q, %q) = %d, want negative", tc.a, tc.b, got)
			case tc.want > 0 && got <= 0:
				t.Fatalf("comparePrerelease(%q, %q) = %d, want positive", tc.a, tc.b, got)
			case tc.want == 0 && got != 0:
				t.Fatalf("comparePrerelease(%q, %q) = %d, want zero", tc.a, tc.b, got)
			}
		})
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

// TestSemVerComparePrereleaseDotSegments pins semver 11.4 ordering: the
// downgrade guard previously compared prereleases lexically, ranking rc.10
// below rc.9 and letting a signed older RC pass. (hasp-g84c)
func TestSemVerComparePrereleaseDotSegments(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0-rc.9", "1.0.0-rc.10", -1}, // numeric, not lexical
		{"1.0.0-rc.10", "1.0.0-rc.9", 1},
		{"1.0.0-rc.2", "1.0.0-rc.2", 0},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},      // shorter set < longer
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1}, // numeric < alphanumeric
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-beta.2", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1}, // numeric, not lexical
		{"1.0.0-beta.11", "1.0.0-rc.1", -1},
	}
	for _, c := range cases {
		a, _ := ParseSemVer(c.a)
		b, _ := ParseSemVer(c.b)
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s vs %s: got %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestCheckUpgradeRefusesPrereleaseDowngrade guards the actual guard: rc.10 -> rc.9
// must be refused even though both are signed prereleases.
func TestCheckUpgradeRefusesPrereleaseDowngrade(t *testing.T) {
	if err := CheckUpgrade("1.0.0-rc.10", "1.0.0-rc.9"); !errors.Is(err, ErrDowngrade) {
		t.Errorf("rc.10 -> rc.9: expected ErrDowngrade, got %v", err)
	}
	if err := CheckUpgrade("1.0.0-rc.9", "1.0.0-rc.10"); err != nil {
		t.Errorf("rc.9 -> rc.10: expected upgrade allowed, got %v", err)
	}
}
