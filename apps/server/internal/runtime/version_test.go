package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVersionUsesEnvAndVersionFileFallback(t *testing.T) {
	origBuildVersion := Version
	defer func() { Version = origBuildVersion }()

	t.Setenv("HASP_VERSION", "9.9.9-test")
	if got := VersionString(); got != "9.9.9-test" {
		t.Fatalf("version from env = %q", got)
	}
	t.Setenv("HASP_VERSION", "")
	Version = ""
	baseDir := t.TempDir()
	versionPath := filepath.Join(baseDir, "VERSION")
	if err := os.WriteFile(versionPath, []byte("1.2.3\n"), 0o600); err != nil {
		t.Fatalf("write version file: %v", err)
	}
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(origWD) }()
	if err := os.Chdir(baseDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if got := VersionString(); got != "1.2.3" {
		t.Fatalf("version from file = %q", got)
	}
}

func TestVersionUsesEmbeddedBuildVersionBeforeRepoFile(t *testing.T) {
	origBuildVersion := Version
	defer func() { Version = origBuildVersion }()

	t.Setenv("HASP_VERSION", "")
	Version = "2.3.4-build"

	baseDir := t.TempDir()
	versionPath := filepath.Join(baseDir, "VERSION")
	if err := os.WriteFile(versionPath, []byte("9.9.9-repo\n"), 0o600); err != nil {
		t.Fatalf("write version file: %v", err)
	}
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(origWD) }()
	if err := os.Chdir(baseDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if got := VersionString(); got != "2.3.4-build" {
		t.Fatalf("version from embedded build = %q", got)
	}
}

func TestVersionFallsBackToDevWhenMissing(t *testing.T) {
	origBuildVersion := Version
	defer func() { Version = origBuildVersion }()

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(origWD) }()
	emptyDir := t.TempDir()
	if err := os.Chdir(emptyDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Setenv("HASP_VERSION", "")
	Version = ""
	if got := VersionString(); got != "0.0.0-dev" {
		t.Fatalf("version fallback = %q", got)
	}
}

func TestVersionFallsBackToDevWhenGetwdFails(t *testing.T) {
	origGetwd := versionGetwd
	origBuildVersion := Version
	defer func() { versionGetwd = origGetwd }()
	defer func() { Version = origBuildVersion }()

	versionGetwd = func() (string, error) { return "", errors.New("getwd failed") }
	t.Setenv("HASP_VERSION", "")
	Version = ""
	if got := VersionString(); got != "0.0.0-dev" {
		t.Fatalf("version fallback on getwd error = %q", got)
	}
}
