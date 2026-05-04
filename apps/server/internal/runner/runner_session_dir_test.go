package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

// bootstrapRunDirHomeDir initializes HASP_HOME under a real (symlink-evaluated)
// path and returns its inject root. Tests that need to reason about the
// runtime layout call this so concurrent runs do not stomp on a shared
// HASP_HOME.
func bootstrapRunDirHomeDir(t *testing.T) (string, string) {
	t.Helper()
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	homeDir := filepath.Join(baseDir, "home")
	t.Setenv(paths.EnvHome, homeDir)
	return homeDir, filepath.Join(homeDir, "runtime", "inject")
}

// TestExecuteWritesInjectedFilesIntoUniqueRunSubdir locks in the per-run
// isolation contract from hasp-ap8: each Execute MUST write under
// `<injectDir>/run-<id>/` rather than the shared top-level inject dir.
// Otherwise two concurrent runs share the same flat namespace and one run's
// startup `cleanupStaleInjectedFiles` deletes the other's in-flight files.
func TestExecuteWritesInjectedFilesIntoUniqueRunSubdir(t *testing.T) {
	_, injectDir := bootstrapRunDirHomeDir(t)

	result, err := Execute(context.Background(), Input{
		Command: []string{"sh", "-c", "printf %s \"$CERT_PATH\""},
		Files:   map[string][]byte{"CERT_PATH": []byte("certificate-data")},
	})
	if err != nil {
		t.Fatalf("execute runner: %v", err)
	}

	emittedPath := strings.TrimSpace(string(result.Stdout))
	if emittedPath == "" {
		t.Fatal("CERT_PATH not exported to child")
	}
	rel, err := filepath.Rel(injectDir, emittedPath)
	if err != nil {
		t.Fatalf("path %q is not under inject dir %q: %v", emittedPath, injectDir, err)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) < 2 {
		t.Fatalf("expected injected file under <injectDir>/run-*/<file>, got rel=%q", rel)
	}
	if !strings.HasPrefix(parts[0], "run-") {
		t.Fatalf("expected per-run subdir prefix `run-`, got %q (full rel=%q)", parts[0], rel)
	}
}

// TestExecuteCleansUpItsOwnRunSubdirOnExit ensures the run-scoped subdir
// disappears when Execute returns, so the inject root does not accumulate
// dead session dirs across normal use.
func TestExecuteCleansUpItsOwnRunSubdirOnExit(t *testing.T) {
	_, injectDir := bootstrapRunDirHomeDir(t)

	if _, err := Execute(context.Background(), Input{
		Command: []string{"sh", "-c", "test -f \"$CERT_PATH\""},
		Files:   map[string][]byte{"CERT_PATH": []byte("certificate-data")},
	}); err != nil {
		t.Fatalf("execute runner: %v", err)
	}

	entries, err := os.ReadDir(injectDir)
	if err != nil {
		t.Fatalf("read inject dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "run-") {
			t.Fatalf("expected run-* subdir to be removed after Execute, found %q", e.Name())
		}
	}
}

// TestConcurrentExecuteDoesNotDeleteEachOthersInjectedFiles is the regression
// test for the original race: two parallel Execute calls used to share the
// flat `hasp-*` namespace and one's startup sweep would delete the other's
// in-flight credential file. With per-run subdirs the sweep only touches
// stale orphan dirs, never the active sibling's files.
func TestConcurrentExecuteDoesNotDeleteEachOthersInjectedFiles(t *testing.T) {
	bootstrapRunDirHomeDir(t)

	const N = 4
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := fmt.Sprintf("payload-%d", i)
			result, err := Execute(context.Background(), Input{
				Command: []string{"sh", "-c", "sleep 0.05; cat \"$CERT_PATH\""},
				Files:   map[string][]byte{"CERT_PATH": []byte(payload)},
			})
			if err != nil {
				errs <- fmt.Errorf("run %d: %w", i, err)
				return
			}
			if string(result.Stdout) != payload {
				errs <- fmt.Errorf("run %d: stdout=%q want %q", i, result.Stdout, payload)
				return
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestExecuteGCRemovesStaleOrphanRunDirs checks that orphaned run-* dirs from
// crashed prior invocations are reclaimed at the start of the next Execute.
// Backdating modtime via os.Chtimes keeps this deterministic without sleeps.
func TestExecuteGCRemovesStaleOrphanRunDirs(t *testing.T) {
	_, injectDir := bootstrapRunDirHomeDir(t)
	if err := os.MkdirAll(injectDir, 0o700); err != nil {
		t.Fatalf("mkdir inject dir: %v", err)
	}

	staleDir := filepath.Join(injectDir, "run-stale")
	freshDir := filepath.Join(injectDir, "run-fresh")
	for _, d := range []string{staleDir, freshDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
		if err := os.WriteFile(filepath.Join(d, "hasp-leak"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write hasp-leak: %v", err)
		}
	}
	stalePast := time.Now().Add(-2 * staleRunDirThreshold)
	if err := os.Chtimes(staleDir, stalePast, stalePast); err != nil {
		t.Fatalf("chtimes stale dir: %v", err)
	}

	if _, err := Execute(context.Background(), Input{Command: []string{"true"}}); err != nil {
		t.Fatalf("execute runner: %v", err)
	}

	if _, err := os.Stat(staleDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected stale run dir to be GC'd, got stat=%v", err)
	}
	if _, err := os.Stat(freshDir); err != nil {
		t.Fatalf("expected fresh run dir to be preserved, got %v", err)
	}
}

// TestWriteInjectedFileRefusesSymlinkResolvingIntoProjectRoot covers the
// EvalSymlinks-based canonicalization called out by hasp-ap8: a planted
// symlink whose Abs path looks safe but whose EvalSymlinks resolves inside
// the project root must be refused. Without this check, an attacker who can
// write into the project root can siphon injected secrets back into it.
func TestWriteInjectedFileRefusesSymlinkResolvingIntoProjectRoot(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	projectRoot := filepath.Join(baseDir, "project")
	innerDir := filepath.Join(projectRoot, "inside")
	if err := os.MkdirAll(innerDir, 0o755); err != nil {
		t.Fatalf("mkdir inside project: %v", err)
	}

	outsideDir := filepath.Join(baseDir, "looks-outside")
	if err := os.Symlink(innerDir, outsideDir); err != nil {
		t.Fatalf("symlink outside->inside: %v", err)
	}

	if _, err := writeInjectedFile(outsideDir, projectRoot, "CERT_PATH", []byte("data")); err == nil || !strings.Contains(err.Error(), "outside the project root") {
		t.Fatalf("expected symlink-resolving-into-project refusal, got %v", err)
	}
}
