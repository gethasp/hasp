package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func TestExecuteInjectsFileOutsideProjectAndCleansUp(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	projectRoot := filepath.Join(baseDir, "project")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("make project root: %v", err)
	}

	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))
	result, err := Execute(context.Background(), Input{
		ProjectRoot: projectRoot,
		Command:     []string{"sh", "-c", "test -f \"$CERT_PATH\" && cat \"$CERT_PATH\""},
		Files: map[string][]byte{
			"CERT_PATH": []byte("certificate-data"),
		},
	})
	if err != nil {
		t.Fatalf("execute runner: %v", err)
	}
	if string(result.Stdout) != "certificate-data" {
		t.Fatalf("stdout = %q", string(result.Stdout))
	}

	entries, err := os.ReadDir(filepath.Join(baseDir, "home", "runtime", "inject"))
	if err != nil {
		t.Fatalf("read inject dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected injected files to be cleaned up, found %d", len(entries))
	}
}

func TestExecuteRunsCommandInsideProjectRoot(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	projectRoot := filepath.Join(baseDir, "project")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("make project root: %v", err)
	}

	t.Setenv(paths.EnvHome, filepath.Join(baseDir, "home"))
	result, err := Execute(context.Background(), Input{
		ProjectRoot: projectRoot,
		Command:     []string{"pwd", "-P"},
	})
	if err != nil {
		t.Fatalf("execute runner: %v", err)
	}
	if got := strings.TrimSpace(string(result.Stdout)); got != projectRoot {
		t.Fatalf("cwd = %q, want %q", got, projectRoot)
	}
}

func TestExecuteFailsForSymlinkedInjectionDir(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	homeDir := filepath.Join(baseDir, "home")
	runtimeDir := filepath.Join(homeDir, "runtime")
	realInjectDir := filepath.Join(baseDir, "real-inject")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatalf("make runtime dir: %v", err)
	}
	if err := os.MkdirAll(realInjectDir, 0o700); err != nil {
		t.Fatalf("make real dir: %v", err)
	}
	if err := os.Symlink(realInjectDir, filepath.Join(runtimeDir, "inject")); err != nil {
		t.Fatalf("symlink inject dir: %v", err)
	}

	t.Setenv(paths.EnvHome, homeDir)
	_, err = Execute(context.Background(), Input{
		Command: []string{"true"},
		Files: map[string][]byte{
			"CERT_PATH": []byte("certificate-data"),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "symlinked injection dir") {
		t.Fatalf("expected symlink refusal, got %v", err)
	}
}

func TestExecuteFailsWhenInjectionDirFallsInsideProject(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	projectRoot := filepath.Join(baseDir, "project")
	homeDir := filepath.Join(projectRoot, ".hasp-home")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("make project root: %v", err)
	}

	t.Setenv(paths.EnvHome, homeDir)
	_, err = Execute(context.Background(), Input{
		ProjectRoot: projectRoot,
		Command:     []string{"true"},
		Files: map[string][]byte{
			"CERT_PATH": []byte("certificate-data"),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "outside the project root") {
		t.Fatalf("expected project-root refusal, got %v", err)
	}
}

func TestExecuteCleansUpStaleInjectedFilesBeforeRun(t *testing.T) {
	baseDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	homeDir := filepath.Join(baseDir, "home")
	injectDir := filepath.Join(homeDir, "runtime", "inject")
	if err := os.MkdirAll(injectDir, 0o700); err != nil {
		t.Fatalf("mkdir inject dir: %v", err)
	}
	stalePath := filepath.Join(injectDir, "hasp-stale")
	if err := os.WriteFile(stalePath, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	t.Setenv(paths.EnvHome, homeDir)
	if _, err := Execute(context.Background(), Input{
		Command: []string{"true"},
	}); err != nil {
		t.Fatalf("execute runner: %v", err)
	}
	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Fatalf("expected stale injected file to be removed, got %v", err)
	}
}
