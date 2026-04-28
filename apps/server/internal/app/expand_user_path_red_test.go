package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// TestExpandUserPath_Empty: empty string → "" with no error.
func TestExpandUserPath_Empty(t *testing.T) {
	got, err := expandUserPath("")
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

// TestExpandUserPath_TildeAlone: "~" alone → os.UserHomeDir().
func TestExpandUserPath_TildeAlone(t *testing.T) {
	t.Setenv("HOME", "/fake/home")
	got, err := expandUserPath("~")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/fake/home" {
		t.Fatalf("expected /fake/home, got %q", got)
	}
}

// TestExpandUserPath_TildeSlashFoo: "~/foo" → filepath.Join(home, "foo").
func TestExpandUserPath_TildeSlashFoo(t *testing.T) {
	t.Setenv("HOME", "/fake/home")
	got, err := expandUserPath("~/foo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join("/fake/home", "foo")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

// TestExpandUserPath_TildeUser: "~user/foo" → error mentioning "~user" and hinting absolute path.
func TestExpandUserPath_TildeUser(t *testing.T) {
	_, err := expandUserPath("~user/foo")
	if err == nil {
		t.Fatal("expected error for ~user expansion, got nil")
	}
	if !strings.Contains(err.Error(), "~user") {
		t.Errorf("error should mention ~user, got: %v", err)
	}
	lower := strings.ToLower(err.Error())
	if !strings.Contains(lower, "not supported") {
		t.Errorf("error should mention 'not supported', got: %v", err)
	}
	if !strings.Contains(lower, "$home") && !strings.Contains(lower, "absolute path") {
		t.Errorf("error should hint $HOME or absolute path, got: %v", err)
	}
}

// TestExpandUserPath_Absolute: "/abs/path" → returned unchanged.
func TestExpandUserPath_Absolute(t *testing.T) {
	got, err := expandUserPath("/abs/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/abs/path" {
		t.Fatalf("expected /abs/path, got %q", got)
	}
}

// TestExpandUserPath_Relative: "rel/path" and "./rel" → returned unchanged.
func TestExpandUserPath_Relative(t *testing.T) {
	for _, in := range []string{"rel/path", "./rel"} {
		got, err := expandUserPath(in)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", in, err)
		}
		if got != in {
			t.Fatalf("relative path %q should be unchanged, got %q", in, got)
		}
	}
}

// TestExpandUserPath_TildeNotAtStart: paths with "~" not at position 0 → returned unchanged.
func TestExpandUserPath_TildeNotAtStart(t *testing.T) {
	in := "/abs/~weird"
	got, err := expandUserPath(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != in {
		t.Fatalf("expected %q unchanged, got %q", in, got)
	}
}

// TestTildeExpansion_ProjectBindTilde: integration test for `project bind --project-root '~/foo'`.
// The green team must call expandUserPath on the flag value before passing to bindProject.
// We fake the vault/store seam and assert the resolved root is filepath.Join(home, "foo"),
// NOT a literal "~/foo" path joined with cwd.
func TestTildeExpansion_ProjectBindTilde(t *testing.T) {
	t.Setenv("HOME", "/fake/home")

	wantRoot := filepath.Join("/fake/home", "foo")
	var capturedRoot string

	// Intercept bindProject by swapping openVaultHandleFn — we need the command to
	// fail early with a sentinel so we can capture what root was resolved.
	// Strategy: override projectCanonicalRootFn to capture the root that reaches it.
	orig := projectCanonicalRootFn
	t.Cleanup(func() { projectCanonicalRootFn = orig })
	projectCanonicalRootFn = func(_ context.Context, root string) (string, error) {
		capturedRoot = root
		// Return root unchanged so we can inspect it; further calls will fail on missing vault.
		return root, nil
	}

	// projectBindCommand will ultimately fail (no vault), but we only care that by the
	// time projectCanonicalRootFn (or bindProject) is reached, the root is already expanded.
	// If expandUserPath is not called, capturedRoot will be "~/foo".
	_ = projectBindCommand(context.Background(), []string{"--project-root", "~/foo", "--hooks=false"}, nopWriter{})

	if capturedRoot == "" {
		// projectCanonicalRootFn may not be called in the bind path; fall back to
		// checking that the command itself returned the expanded root in its output
		// (handled by renderProjectBinding). In that case this test is inconclusive
		// and will fail with a message directing the green team to hook the right spot.
		t.Fatal("capturedRoot is empty: expandUserPath was not called before the store seam; green team must wire expandUserPath into projectBindCommand")
	}

	if capturedRoot == "~/foo" {
		t.Fatalf("project bind passed literal '~/foo' to store layer; want %q — expandUserPath must be called on the --project-root flag value", wantRoot)
	}

	if capturedRoot != wantRoot {
		t.Fatalf("project bind resolved root = %q; want %q", capturedRoot, wantRoot)
	}
}

// nopWriter discards output.
type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
