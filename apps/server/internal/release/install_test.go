package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func makeTarball(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o755,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	return buf.Bytes()
}

func TestExtractBinaryHappyPath(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "hasp.new")
	tarball := makeTarball(t, map[string][]byte{
		"hasp": []byte("\x7fELFfake-binary"),
	})
	if err := ExtractBinary(tarball, "hasp", dst); err != nil {
		t.Fatalf("ExtractBinary: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "\x7fELFfake-binary" {
		t.Fatalf("unexpected content: %q", got)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("expected 0755, got %#o", info.Mode().Perm())
	}
}

func TestExtractBinaryAcceptsNestedPath(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "hasp.new")
	tarball := makeTarball(t, map[string][]byte{
		"hasp-v1.0.0-darwin-arm64/hasp": []byte("nested-binary"),
	})
	if err := ExtractBinary(tarball, "hasp", dst); err != nil {
		t.Fatalf("ExtractBinary: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "nested-binary" {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestExtractBinaryRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "hasp.new")
	tarball := makeTarball(t, map[string][]byte{
		"../../../etc/sudo/hasp": []byte("evil"),
	})
	err := ExtractBinary(tarball, "hasp", dst)
	if !errors.Is(err, ErrUnsafeTarball) {
		t.Fatalf("expected ErrUnsafeTarball, got %v", err)
	}
}

func TestExtractBinaryEmpty(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "hasp.new")
	tarball := makeTarball(t, map[string][]byte{
		"README.md": []byte("hi"),
	})
	err := ExtractBinary(tarball, "hasp", dst)
	if !errors.Is(err, ErrTarballEmpty) {
		t.Fatalf("expected ErrTarballEmpty, got %v", err)
	}
}

func TestAtomicReplaceSameDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hasp")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatalf("seed: %v", err)
	}
	staged := filepath.Join(dir, "hasp.new")
	if err := os.WriteFile(staged, []byte("new"), 0o755); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := AtomicReplace(staged, target); err != nil {
		t.Fatalf("AtomicReplace: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "new" {
		t.Fatalf("expected 'new' after swap, got %q", got)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatalf("expected staged file to be gone, err=%v", err)
	}
}

func TestAtomicReplaceRefusesCrossDir(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	staged := filepath.Join(a, "hasp.new")
	target := filepath.Join(b, "hasp")
	if err := os.WriteFile(staged, []byte("new"), 0o755); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := AtomicReplace(staged, target); err == nil {
		t.Fatal("expected cross-directory rename to be refused")
	}
}

func TestStagingPathIsSibling(t *testing.T) {
	got, err := StagingPath("/usr/local/bin/hasp")
	if err != nil {
		t.Fatalf("StagingPath: %v", err)
	}
	if filepath.Dir(got) != "/usr/local/bin" {
		t.Fatalf("expected sibling path, got %s", got)
	}
}
