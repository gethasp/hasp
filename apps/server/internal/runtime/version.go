package runtime

import (
	"os"
	"path/filepath"
	"strings"
)

var versionGetwd = os.Getwd

// Version, Commit, and BuildDate are the ldflags injection targets.
// Default values are used when the binary is built without -X flags
// (e.g. plain `go build` during development).
//
// ldflags injection example:
//
//	-X github.com/gethasp/hasp/apps/server/internal/runtime.Version=1.2.3
//	-X github.com/gethasp/hasp/apps/server/internal/runtime.Commit=abc1234
//	-X github.com/gethasp/hasp/apps/server/internal/runtime.BuildDate=2026-04-26T00:00:00Z
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// VersionString returns the effective version string.  Priority order:
//  1. HASP_VERSION env var (overrides for testing/CI)
//  2. Version ldflags var (set by build.sh)
//  3. VERSION file discovered by walking up from cwd
//  4. "0.0.0-dev" fallback
func VersionString() string {
	if value := strings.TrimSpace(os.Getenv("HASP_VERSION")); value != "" {
		return value
	}
	if value := strings.TrimSpace(Version); value != "" && value != "dev" {
		return value
	}
	dir, err := versionGetwd()
	if err != nil {
		return "0.0.0-dev"
	}
	current := dir
	for {
		versionPath := filepath.Join(current, "VERSION")
		if data, readErr := os.ReadFile(versionPath); readErr == nil {
			value := strings.TrimSpace(string(data))
			if value != "" {
				return value
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "0.0.0-dev"
}

// CommitString returns the git commit hash baked in at link time, or
// "unknown" when the binary was built without -X Commit=...
func CommitString() string {
	if value := strings.TrimSpace(Commit); value != "" {
		return value
	}
	return "unknown"
}

// BuildDateString returns the build timestamp baked in at link time, or
// "unknown" when the binary was built without -X BuildDate=...
func BuildDateString() string {
	if value := strings.TrimSpace(BuildDate); value != "" {
		return value
	}
	return "unknown"
}
