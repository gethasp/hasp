//go:build hasp_test_fastkdf

package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigureEnvelopeDurabilityForTests(t *testing.T) {
	restore := ConfigureEnvelopeDurabilityForTests()
	defer restore()
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "state.tmp")
	newPath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(oldPath, []byte("sealed"), 0o600); err != nil {
		t.Fatalf("write temp envelope: %v", err)
	}
	if err := fsyncFileFn(nil); err != nil {
		t.Fatalf("fast fsync file: %v", err)
	}
	if err := fsyncDirFn(dir); err != nil {
		t.Fatalf("fast fsync dir: %v", err)
	}
	if err := renameEnvelopeFn(oldPath, newPath); err != nil {
		t.Fatalf("fast rename: %v", err)
	}
	data, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatalf("read new envelope: %v", err)
	}
	if string(data) != "sealed" {
		t.Fatalf("unexpected envelope data %q", data)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("expected temp envelope removed, got %v", err)
	}
	if err := renameEnvelopeFn(filepath.Join(dir, "missing.tmp"), filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected fast rename missing-source error")
	}
}
