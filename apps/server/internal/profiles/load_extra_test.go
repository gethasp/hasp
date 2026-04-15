package profiles

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDirEmptyDirectory(t *testing.T) {
	profiles, err := LoadDir(t.TempDir())
	if err != nil {
		t.Fatalf("load empty dir: %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("expected empty profile list, got %d", len(profiles))
	}
}

func TestLoadDirMissingDirectoryFails(t *testing.T) {
	if _, err := LoadDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected missing directory error")
	}
}

func TestLoadDirIgnoresNonJSONFilesAndSortsProfiles(t *testing.T) {
	dir := t.TempDir()
	writeProfile := func(name string, profile Profile) {
		t.Helper()
		data, err := json.Marshal(profile)
		if err != nil {
			t.Fatalf("marshal profile: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatalf("write profile %s: %v", name, err)
		}
	}
	writeProfile("zeta.json", Profile{
		ID:                   "zeta",
		Name:                 "Zeta",
		Transport:            "stdio",
		Command:              []string{"hasp", "mcp"},
		ProjectBindingRecipe: "manual",
		ApprovalPath:         "session",
		SafeInjectPath:       "inject",
		WriteEnvPath:         "write-env",
		RegressionFixture:    "fixture",
		DocsPath:             "docs",
	})
	writeProfile("alpha.json", Profile{
		ID:                   "alpha",
		Name:                 "Alpha",
		Transport:            "stdio",
		Command:              []string{"hasp", "mcp"},
		ProjectBindingRecipe: "manual",
		ApprovalPath:         "session",
		SafeInjectPath:       "inject",
		WriteEnvPath:         "write-env",
		RegressionFixture:    "fixture",
		DocsPath:             "docs",
	})
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ignore"), 0o600); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatalf("mkdir ignored subdir: %v", err)
	}
	profiles, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("load dir: %v", err)
	}
	if len(profiles) != 2 || profiles[0].ID != "alpha" || profiles[1].ID != "zeta" {
		t.Fatalf("unexpected sorted profiles: %+v", profiles)
	}
}

func TestLoadDirPropagatesReadAndValidationErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "missing.json"), filepath.Join(dir, "broken.json")); err != nil {
		t.Fatalf("create broken symlink: %v", err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected read error from broken symlink")
	}

	dir2 := t.TempDir()
	data, err := json.Marshal(Profile{ID: "id", Name: "name", Transport: "stdio", Command: []string{"hasp"}, ProjectBindingRecipe: "manual"})
	if err != nil {
		t.Fatalf("marshal partial profile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "partial.json"), data, 0o600); err != nil {
		t.Fatalf("write partial profile: %v", err)
	}
	if _, err := LoadDir(dir2); err == nil {
		t.Fatal("expected validation error from partial profile")
	}
}
