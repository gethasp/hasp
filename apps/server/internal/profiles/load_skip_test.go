package profiles

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDirSkipsNonJSONEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("ignore"), 0o600); err != nil {
		t.Fatalf("write txt file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	profiles, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("load dir: %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("expected no profiles, got %d", len(profiles))
	}
}
