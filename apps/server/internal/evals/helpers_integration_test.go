//go:build integration

package evals

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

type evalEnv struct {
	repoRoot       string
	binary         string
	home           string
	socket         string
	profilesDir    string
	projectRoot    string
	masterPassword string
	backupPass     string
}

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	current := dir
	for {
		if _, err := os.Stat(filepath.Join(current, "VERSION")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("repo root not found")
		}
		current = parent
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		root := repoRoot(t)
		outDir, err := os.MkdirTemp("", "hasp-evals-bin")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(outDir, "hasp")
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/hasp")
		cmd.Dir = filepath.Join(root, "apps", "server")
		output, err := cmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("build hasp: %w: %s", err, string(output))
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

func newEvalEnv(t *testing.T) evalEnv {
	t.Helper()
	root := repoRoot(t)
	projectParent := t.TempDir()
	projectRoot := filepath.Join(projectParent, "repo")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	initGitRepo(t, projectRoot)
	return evalEnv{
		repoRoot:       root,
		binary:         buildBinary(t),
		home:           t.TempDir(),
		socket:         filepath.Join("/tmp", fmt.Sprintf("hasp-evals-%d.sock", time.Now().UnixNano())),
		profilesDir:    filepath.Join(root, "apps", "server", "profiles"),
		projectRoot:    projectRoot,
		masterPassword: "integration-master-password",
		backupPass:     "integration-backup-passphrase",
	}
}

func initGitRepo(t *testing.T, repo string) {
	t.Helper()
	runCmd(t, repo, nil, "git", "init")
	runCmd(t, repo, nil, "git", "config", "user.name", "HASP Eval")
	runCmd(t, repo, nil, "git", "config", "user.email", "eval@gethasp.com")
}

func (e evalEnv) commandEnv(extra map[string]string) []string {
	env := os.Environ()
	env = append(env,
		"HASP_HOME="+e.home,
		"HASP_SOCKET="+e.socket,
		"HASP_MASTER_PASSWORD="+e.masterPassword,
		"HASP_BACKUP_PASSPHRASE="+e.backupPass,
		"HASP_PROFILES_DIR="+e.profilesDir,
	)
	for key, value := range extra {
		env = append(env, key+"="+value)
	}
	return env
}

func runHasp(t *testing.T, e evalEnv, stdin string, args ...string) (string, string, error) {
	t.Helper()
	return runCmdWithInput(t, e.projectRoot, e.commandEnv(nil), stdin, e.binary, args...)
}

func runCmd(t *testing.T, cwd string, env []string, name string, args ...string) (string, string) {
	t.Helper()
	stdout, stderr, err := runCmdWithInput(t, cwd, env, "", name, args...)
	if err != nil {
		t.Fatalf("run %s %v: %v\nstdout:\n%s\nstderr:\n%s", name, args, err, stdout, stderr)
	}
	return stdout, stderr
}

func runCmdWithInput(t *testing.T, cwd string, env []string, stdin string, name string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	if env != nil {
		cmd.Env = env
	}
	if stdin != "" {
		cmd.Stdin = bytes.NewBufferString(stdin)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func parseJSONMap(t *testing.T, raw string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("decode json %q: %v", raw, err)
	}
	return out
}

func openRuntimeSession(t *testing.T, e evalEnv, projectRoot string, ttlSeconds int) string {
	t.Helper()
	t.Setenv(paths.EnvHome, e.home)
	t.Setenv(paths.EnvSocket, e.socket)
	if _, _, err := runHasp(t, e, "", "status"); err != nil {
		t.Fatalf("start daemon via status: %v", err)
	}
	manager, err := runtime.NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	client, err := runtime.Dial(context.Background(), manager.SocketPath())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:   "integration-test",
		ProjectRoot: projectRoot,
		TTLSeconds:  ttlSeconds,
	})
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	return reply.SessionToken
}

func revokeRuntimeSession(t *testing.T, e evalEnv, token string) {
	t.Helper()
	t.Setenv(paths.EnvHome, e.home)
	t.Setenv(paths.EnvSocket, e.socket)
	manager, err := runtime.NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	client, err := runtime.Dial(context.Background(), manager.SocketPath())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	if err := client.RevokeSession(context.Background(), token); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
}

func packageArtifact(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	stdout, _ := runCmd(t, root, nil, "bash", "./scripts/package-release.sh")
	return strings.TrimSpace(stdout)
}
