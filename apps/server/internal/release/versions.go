package release

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrDowngrade is returned when the requested target version sorts
// lower than (or equal to) the running binary's version. Downgrade
// rejection is a deliberate rollback-attack defence; users who really
// want an older binary must download it manually.
var ErrDowngrade = errors.New("refusing to downgrade")

// ErrInvalidVersion is returned for unparseable version strings.
var ErrInvalidVersion = errors.New("invalid version string")

// SemVer is a minimal semver-2.0 representation: MAJOR.MINOR.PATCH
// with an optional dash-prefixed prerelease tag. Build metadata
// (anything after a '+') is ignored — it does not participate in
// ordering.
type SemVer struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
}

// ParseSemVer accepts "v1.2.3", "1.2.3", "v1.2.3-rc.1", "1.2.3+build".
func ParseSemVer(s string) (SemVer, error) {
	out := SemVer{}
	trimmed := strings.TrimSpace(s)
	trimmed = strings.TrimPrefix(trimmed, "v")
	if trimmed == "" {
		return out, fmt.Errorf("%w: empty", ErrInvalidVersion)
	}
	if idx := strings.IndexByte(trimmed, '+'); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	core := trimmed
	if idx := strings.IndexByte(trimmed, '-'); idx >= 0 {
		core = trimmed[:idx]
		out.Prerelease = trimmed[idx+1:]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return out, fmt.Errorf("%w: %q must have MAJOR.MINOR.PATCH", ErrInvalidVersion, s)
	}
	for i, dst := range []*int{&out.Major, &out.Minor, &out.Patch} {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return SemVer{}, fmt.Errorf("%w: %q component %d: %v", ErrInvalidVersion, s, i, err)
		}
		*dst = n
	}
	return out, nil
}

// Compare returns -1/0/+1 in the usual sense. A version with a
// prerelease tag sorts BELOW the same MAJOR.MINOR.PATCH without one
// (1.0.0-rc.1 < 1.0.0), per semver 11.3. Prereleases compare by
// dot-segment per semver 11.4, so rc.9 < rc.10 (numeric segments compare
// numerically). A purely lexical compare would wrongly rank rc.10 < rc.9
// and let a signed older RC pass the downgrade guard.
func (a SemVer) Compare(b SemVer) int {
	if a.Major != b.Major {
		if a.Major < b.Major {
			return -1
		}
		return 1
	}
	if a.Minor != b.Minor {
		if a.Minor < b.Minor {
			return -1
		}
		return 1
	}
	if a.Patch != b.Patch {
		if a.Patch < b.Patch {
			return -1
		}
		return 1
	}
	switch {
	case a.Prerelease == b.Prerelease:
		return 0
	case a.Prerelease == "":
		return 1
	case b.Prerelease == "":
		return -1
	default:
		return comparePrerelease(a.Prerelease, b.Prerelease)
	}
}

// comparePrerelease orders two non-empty prerelease strings per semver 11.4:
// split on '.', compare identifier by identifier. Numeric identifiers compare
// numerically; numeric always sorts below alphanumeric; alphanumeric compare in
// ASCII order; and when all leading identifiers match, the longer set wins.
func comparePrerelease(a, b string) int {
	aSeg := strings.Split(a, ".")
	bSeg := strings.Split(b, ".")
	for i := 0; i < len(aSeg) && i < len(bSeg); i++ {
		if aSeg[i] == bSeg[i] {
			continue
		}
		aNum, aErr := strconv.Atoi(aSeg[i])
		bNum, bErr := strconv.Atoi(bSeg[i])
		aIsNum := aErr == nil
		bIsNum := bErr == nil
		switch {
		case aIsNum && bIsNum:
			if aNum != bNum {
				if aNum < bNum {
					return -1
				}
				return 1
			}
		case aIsNum: // numeric identifiers sort below alphanumeric
			return -1
		case bIsNum:
			return 1
		default:
			return strings.Compare(aSeg[i], bSeg[i])
		}
	}
	switch {
	case len(aSeg) < len(bSeg):
		return -1
	case len(aSeg) > len(bSeg):
		return 1
	default:
		return 0
	}
}

// String renders back to "MAJOR.MINOR.PATCH[-prerelease]".
func (v SemVer) String() string {
	core := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		return core + "-" + v.Prerelease
	}
	return core
}

// CheckUpgrade compares a candidate target against the currently
// running version. Returns ErrDowngrade for any non-strict upgrade
// (older or same version).
func CheckUpgrade(currentRaw, targetRaw string) error {
	current, err := ParseSemVer(currentRaw)
	if err != nil {
		return fmt.Errorf("current version: %w", err)
	}
	target, err := ParseSemVer(targetRaw)
	if err != nil {
		return fmt.Errorf("target version: %w", err)
	}
	cmp := current.Compare(target)
	if cmp == 0 {
		return fmt.Errorf("%w: already at %s", ErrDowngrade, target)
	}
	if cmp > 0 {
		return fmt.Errorf("%w: %s is older than installed %s", ErrDowngrade, target, current)
	}
	return nil
}
