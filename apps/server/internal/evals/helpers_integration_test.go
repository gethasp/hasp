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
	"strconv"
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
	userHome       string
	configHome     string
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
	binary := buildBinary(t)
	projectParent := t.TempDir()
	projectRoot := filepath.Join(projectParent, "repo")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	initGitRepo(t, projectRoot)
	userHome := t.TempDir()
	configHome := filepath.Join(userHome, ".config")
	t.Setenv("HOME", userHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	env := evalEnv{
		repoRoot:       root,
		binary:         binary,
		home:           t.TempDir(),
		socket:         filepath.Join("/tmp", fmt.Sprintf("hasp-evals-%d.sock", time.Now().UnixNano())),
		userHome:       userHome,
		configHome:     configHome,
		profilesDir:    filepath.Join(root, "apps", "server", "profiles"),
		projectRoot:    projectRoot,
		masterPassword: "integration-master-password",
		backupPass:     "integration-backup-passphrase",
	}
	t.Cleanup(func() {
		stopEvalDaemon(t, env)
	})
	return env
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
		"HOME="+e.userHome,
		"HASP_HOME="+e.home,
		"HASP_SOCKET="+e.socket,
		"HASP_MASTER_PASSWORD="+e.masterPassword,
		"HASP_BACKUP_PASSPHRASE="+e.backupPass,
		"HASP_PROFILES_DIR="+e.profilesDir,
		"XDG_CONFIG_HOME="+e.configHome,
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

// waitForEvalSocket polls until socketPath exists or fails the test after a
// generous deadline. `hasp daemon start` returns as soon as the broker is
// spawned; the socket bind happens shortly after, so eval helpers must wait
// before dialing.
func waitForEvalSocket(t *testing.T, socketPath string) {
	t.Helper()
	if strings.TrimSpace(socketPath) == "" {
		return
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for daemon socket %s", socketPath)
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
	return openRuntimeSessionWithDuration(t, e, projectRoot, time.Duration(ttlSeconds)*time.Second)
}

// openRuntimeSessionWithDuration is the sub-second-aware analogue of
// openRuntimeSession. When ttl is < 1s the request is sent over the wire as
// TTLMillis so the daemon honours the precise duration; otherwise it falls
// back to TTLSeconds for back-compat with older daemons. hasp-4xf9.
func openRuntimeSessionWithDuration(t *testing.T, e evalEnv, projectRoot string, ttl time.Duration) string {
	t.Helper()
	t.Setenv(paths.EnvHome, e.home)
	t.Setenv(paths.EnvSocket, e.socket)
	// hasp-qe5h made `hasp status` connect-only (it no longer auto-starts the
	// daemon when the socket is missing); use `daemon start` so the eval
	// helper actually has a running broker before the dial below.
	if _, _, err := runHasp(t, e, "", "daemon", "start"); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	// `daemon start` spawns the broker asynchronously and returns before the
	// socket has been bound; poll until the socket file appears so the dial
	// below sees a ready broker instead of ENOENT.
	waitForEvalSocket(t, e.socket)
	manager, err := runtime.NewManager()
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	client, err := runtime.Dial(context.Background(), manager.SocketPath())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	defer client.Close()
	req := runtime.OpenSessionRequest{
		HostLabel:   "integration-test",
		ProjectRoot: projectRoot,
	}
	if ttl > 0 && ttl < time.Second {
		req.TTLMillis = int(ttl / time.Millisecond)
	} else {
		req.TTLSeconds = int(ttl.Seconds())
	}
	reply, err := client.OpenSession(context.Background(), req)
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

func stopEvalDaemon(t *testing.T, e evalEnv) {
	t.Helper()
	if strings.TrimSpace(e.binary) == "" || strings.TrimSpace(e.home) == "" {
		return
	}

	pidPath := filepath.Join(e.home, "runtime", "daemon.pid")
	socketPath := e.socket
	if socketPath == "" {
		socketPath = filepath.Join(e.home, "runtime", "daemon.sock")
	}
	pid := ""
	verified := false
	if data, err := os.ReadFile(pidPath); err == nil {
		pid = strings.TrimSpace(string(data))
		if pidValue, convErr := strconv.Atoi(pid); convErr == nil && pidValue > 0 {
			verified = verifyScopedEvalDaemon(t, pidValue, socketPath)
		}
	}

	if verified {
		_, _, _ = runCmdWithInput(t, e.projectRoot, e.commandEnv(nil), "", e.binary, "daemon", "stop")
	}

	if verified && pid != "" {
		if pidValue, convErr := strconv.Atoi(pid); convErr == nil && pidValue > 0 {
			if proc, findErr := os.FindProcess(pidValue); findErr == nil {
				_ = proc.Kill()
			}
		}
	}

	_ = os.Remove(pidPath)
	_ = os.Remove(socketPath)
}

func verifyScopedEvalDaemon(t *testing.T, pid int, socketPath string) bool {
	t.Helper()
	if pid <= 0 || strings.TrimSpace(socketPath) == "" {
		return false
	}
	client, err := runtime.Dial(context.Background(), socketPath)
	if err != nil {
		return false
	}
	defer client.Close()
	reply, err := client.Status(context.Background())
	if err != nil {
		return false
	}
	return reply.PID == pid && reply.SocketPath == socketPath
}

func (e evalEnv) withScopedHome(home string, userHome string) evalEnv {
	scoped := e
	if strings.TrimSpace(home) != "" {
		scoped.home = home
	}
	if strings.TrimSpace(userHome) != "" {
		scoped.userHome = userHome
		scoped.configHome = filepath.Join(userHome, ".config")
	}
	return scoped
}

func TestNewEvalEnvScopesCLIConfig(t *testing.T) {
	env := newEvalEnv(t)

	if got := os.Getenv("HOME"); got != env.userHome {
		t.Fatalf("HOME = %q, want %q", got, env.userHome)
	}
	if got := os.Getenv("XDG_CONFIG_HOME"); got != env.configHome {
		t.Fatalf("XDG_CONFIG_HOME = %q, want %q", got, env.configHome)
	}

	configPath, err := paths.ConfigPath()
	if err != nil {
		t.Fatalf("config path: %v", err)
	}
	if !strings.HasPrefix(configPath, env.userHome+string(os.PathSeparator)) {
		t.Fatalf("config path = %q, want prefix %q", configPath, env.userHome)
	}
	if filepath.Base(configPath) != "hasp-cli.json" {
		t.Fatalf("config path = %q, want basename hasp-cli.json", configPath)
	}

	if err := paths.SaveConfig(paths.CLIConfig{HomeDir: env.home}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("expected scoped config file at %s: %v", configPath, err)
	}
}

func TestStopEvalDaemonStopsDetachedDaemon(t *testing.T) {
	env := newEvalEnv(t)

	// hasp-qe5h made `hasp status` connect-only; use `daemon start` so the
	// detached daemon actually exists for the cleanup-verification below.
	if _, _, err := runHasp(t, env, "", "daemon", "start"); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	// Wait for the daemon to bind its socket before we read pid state and
	// invoke cleanup; otherwise the verify path can't talk to the broker.
	waitForEvalSocket(t, env.socket)

	pidPath := filepath.Join(env.home, "runtime", "daemon.pid")
	pidData, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("expected pid file before cleanup: %v", err)
	}
	pidValue, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil || pidValue <= 0 {
		t.Fatalf("expected valid daemon pid, got %q err=%v", strings.TrimSpace(string(pidData)), err)
	}

	stopEvalDaemon(t, env)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, pidErr := os.Stat(pidPath)
		_, socketErr := os.Stat(env.socket)
		processErr := exec.Command("ps", "-p", strconv.Itoa(pidValue), "-o", "pid=").Run()
		if os.IsNotExist(pidErr) && os.IsNotExist(socketErr) && processErr != nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}

	t.Fatalf("expected daemon cleanup to remove pid file %s, socket %s, and process %d", pidPath, env.socket, pidValue)
}

func TestStopEvalDaemonSkipsUnverifiedPID(t *testing.T) {
	env := newEvalEnv(t)
	runtimeDir := filepath.Join(env.home, "runtime")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}

	cmd := exec.Command("sh", "-c", "sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleeper: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	pidPath := filepath.Join(runtimeDir, "daemon.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	stopEvalDaemon(t, env)

	if err := exec.Command("ps", "-p", strconv.Itoa(cmd.Process.Pid), "-o", "pid=").Run(); err != nil {
		t.Fatalf("expected unrelated process %d to survive cleanup: %v", cmd.Process.Pid, err)
	}
}
