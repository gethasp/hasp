package app

import (
	"os"
	"path/filepath"
	"strings"
)

type haspPathCandidate struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
}

type haspPathDiagnostics struct {
	Executable string              `json:"executable,omitempty"`
	First      string              `json:"first,omitempty"`
	Candidates []haspPathCandidate `json:"candidates,omitempty"`
	Shadowed   bool                `json:"shadowed"`
	HasNewer   bool                `json:"has_newer"`
	Warning    string              `json:"warning,omitempty"`
}

var (
	pathDiagnosticsExecutableFn = os.Executable
	pathDiagnosticsLookupEnvFn  = os.Getenv
	pathDiagnosticsStatFn       = os.Stat
	pathDiagnosticsEvalSymlinks = filepath.EvalSymlinks
)

func detectHaspPathDiagnostics(currentVersion string) haspPathDiagnostics {
	if strings.TrimSpace(pathDiagnosticsLookupEnvFn("HASP_SKIP_PATH_DIAGNOSTICS")) != "" {
		return haspPathDiagnostics{}
	}
	executable, _ := pathDiagnosticsExecutableFn()
	executable = cleanComparablePath(executable)
	if executable == "" || filepath.Base(executable) != "hasp" {
		return haspPathDiagnostics{}
	}

	candidates := haspPathCandidates(pathDiagnosticsLookupEnvFn("PATH"))
	if len(candidates) == 0 {
		return haspPathDiagnostics{Executable: executable}
	}
	for i := range candidates {
		if cleanComparablePath(candidates[i].Path) == executable {
			candidates[i].Version = strings.TrimSpace(currentVersion)
			continue
		}
		candidates[i].Version = inferHaspCandidateVersion(candidates[i].Path)
	}

	report := haspPathDiagnostics{
		Executable: executable,
		First:      candidates[0].Path,
		Candidates: candidates,
		Shadowed:   cleanComparablePath(candidates[0].Path) != executable,
	}
	newer := newestOtherCandidate(candidates, executable, currentVersion)
	if newer.Path != "" {
		report.HasNewer = true
	}
	report.Warning = buildHaspPathWarning(report, newer, currentVersion)
	return report
}

func haspPathCandidates(pathValue string) []haspPathCandidate {
	seen := map[string]struct{}{}
	var out []haspPathCandidate
	for _, dir := range filepath.SplitList(pathValue) {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		candidate := filepath.Join(dir, "hasp")
		info, err := pathDiagnosticsStatFn(candidate)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		clean := cleanComparablePath(candidate)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, haspPathCandidate{Path: candidate})
	}
	return out
}

func cleanComparablePath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	if resolved, err := pathDiagnosticsEvalSymlinks(path); err == nil {
		path = resolved
	}
	return filepath.Clean(path)
}

func inferHaspCandidateVersion(path string) string {
	resolved := filepath.ToSlash(cleanComparablePath(path))
	parts := strings.Split(resolved, "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "hasp" && looksLikeSemver(parts[i+1]) {
			return strings.TrimPrefix(parts[i+1], "v")
		}
	}
	return ""
}

func looksLikeSemver(version string) bool {
	trimmed := strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func newestOtherCandidate(candidates []haspPathCandidate, executable string, currentVersion string) haspPathCandidate {
	current := parseSemverParts(currentVersion)
	var best haspPathCandidate
	for _, candidate := range candidates {
		if cleanComparablePath(candidate.Path) == executable || strings.TrimSpace(candidate.Version) == "" {
			continue
		}
		if compareSemverParts(parseSemverParts(candidate.Version), current) <= 0 {
			continue
		}
		if best.Path == "" || compareSemverParts(parseSemverParts(candidate.Version), parseSemverParts(best.Version)) > 0 {
			best = candidate
		}
	}
	return best
}

func buildHaspPathWarning(report haspPathDiagnostics, newer haspPathCandidate, currentVersion string) string {
	switch {
	case newer.Path != "":
		return "newer hasp " + newer.Version + " is on PATH at " + newer.Path + ", but this shell is running " + currentVersion + " from " + report.Executable + "; move the newer directory earlier in PATH, remove the stale binary, then run hash -r"
	case report.Shadowed:
		return "this hasp executable is shadowed by " + report.First + "; move " + filepath.Dir(report.Executable) + " earlier in PATH or remove the earlier binary, then run hash -r"
	case len(report.Candidates) > 1:
		others := make([]string, 0, len(report.Candidates)-1)
		for _, candidate := range report.Candidates[1:] {
			others = append(others, candidate.Path)
		}
		return "multiple hasp executables are on PATH; this shell runs " + report.First + ", later candidates: " + strings.Join(others, ", ")
	default:
		return ""
	}
}

func parseSemverParts(version string) [3]int {
	major, minor, patch := parseVersionParts(version)
	return [3]int{major, minor, patch}
}

func compareSemverParts(a, b [3]int) int {
	for i := range a {
		if a[i] > b[i] {
			return 1
		}
		if a[i] < b[i] {
			return -1
		}
	}
	return 0
}
