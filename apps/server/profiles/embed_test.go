package profilesdata

import (
	"io/fs"
	"testing"
)

func TestEmbeddedProfilesIncludeCatalogAndReleaseGates(t *testing.T) {
	files, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatalf("read embedded profiles: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected embedded profile files")
	}
	foundProfile := false
	foundReleaseGates := false
	for _, file := range files {
		switch file.Name() {
		case "claude-code.json":
			foundProfile = true
		case "release-gates.json":
			foundReleaseGates = true
		}
	}
	if !foundProfile || !foundReleaseGates {
		t.Fatalf("embedded files missing expected entries: profile=%v gates=%v", foundProfile, foundReleaseGates)
	}
}
