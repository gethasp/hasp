package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

type injectedTempFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Close() error
}

// staleRunDirThreshold is how long a `run-*` subdir under the inject root may
// linger after its creation modtime before the next Execute call reclaims it.
// One hour is well past any reasonable `hasp run` lifetime so a healthy run
// is never reclaimed mid-flight, but short enough that crashed runs do not
// leak credentials onto disk indefinitely. Tests can override this for
// deterministic GC assertions.
var staleRunDirThreshold = time.Hour

// runDirPrefix is the per-Execute subdir prefix under the shared inject root.
// Each call generates `<injectDir>/run-<rand>/` so concurrent calls cannot
// collide and one call's startup sweep cannot delete a sibling's in-flight
// credential file.
const runDirPrefix = "run-"

// legacyInjectedFilePrefix matched the flat `<injectDir>/hasp-*` layout used
// before per-run subdirs. The cleanup pass keeps recognising it so a binary
// upgrade does not strand orphan credential files from older runs.
const legacyInjectedFilePrefix = "hasp-"

var (
	resolveRunnerPaths = paths.Resolve
	runnerAbsPath      = filepath.Abs
	runnerEvalSymlinks = filepath.EvalSymlinks
	lstatInjectionPath = os.Lstat
	mkdirAllInjection  = os.MkdirAll
	readInjectionDir   = os.ReadDir
	removeInjectedPath = os.Remove
	removeInjectedTree = os.RemoveAll
	statInjectedPath   = os.Stat
	createTempFile     = func(dir string, pattern string) (injectedTempFile, error) {
		return os.CreateTemp(dir, pattern)
	}
	randReadRunner = rand.Read
	timeNowRunner  = time.Now
)

// Input describes a brokered execution request. Env entries override any
// same-named variable inherited from the parent process — exec.Cmd's
// "duplicate keys: last value wins" rule does the override automatically
// because Execute appends Env after the filtered parent environment.
//
// Stdin, Stdout, and Stderr are optional streaming I/O seams:
//   - When Stdin is non-nil, it is wired as the child's stdin.
//   - When Stdout/Stderr are non-nil, the child writes directly into them
//     and Result.Stdout/Result.Stderr will be nil (legacy buffered fields
//     are only populated when the corresponding writer is nil).
//   - When Stdout/Stderr are nil the legacy behaviour is preserved:
//     output is buffered internally and returned in Result.Stdout/Stderr.
//
// TTY requests PTY allocation: the runner opens a pty pair, attaches the
// slave to the child's stdin/stdout/stderr, and pipes the master end through
// the caller's Stdin/Stdout. Stderr is merged into Stdout because PTYs do
// not preserve stream separation. Callers must wrap Stdout with
// redactor.NewStreamingWriterANSIAware (not NewStreamingWriter) when TTY is
// true, otherwise children that emit colour escapes can split secrets across
// ANSI sequences and bypass redaction. Only honoured on darwin and linux;
// silently falls back to the non-TTY path on unsupported platforms.
// hasp-ymuy.
type Input struct {
	ProjectRoot string
	Command     []string
	Env         map[string]string
	Files       map[string][]byte

	// Optional streaming I/O. nil means use the legacy buffered path.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	TTY bool
}

// Result holds the outcome of a brokered execution.
//
// Result.Stdout and Result.Stderr are populated only when Input.Stdout and
// Input.Stderr were nil (the legacy buffered path). When custom writers were
// provided, those fields will be nil — output was streamed directly into the
// supplied writers.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

func Execute(ctx context.Context, input Input) (Result, error) {
	if len(input.Command) == 0 {
		return Result{}, errors.New("command is required")
	}
	runtimePaths, err := resolveRunnerPaths()
	if err != nil {
		return Result{}, err
	}
	injectDir := filepath.Join(runtimePaths.RuntimeDir, "inject")
	if err := ensureInjectionDir(injectDir, runtimePaths.HomeDir); err != nil {
		return Result{}, err
	}
	if err := cleanupStaleInjectedFiles(injectDir); err != nil {
		return Result{}, err
	}

	runDir, removeRunDir, err := prepareRunInjectDir(injectDir)
	if err != nil {
		return Result{}, err
	}
	defer removeRunDir()

	env := filterChildEnv(os.Environ())
	for name, value := range input.Env {
		env = append(env, fmt.Sprintf("%s=%s", name, value))
	}

	for envName, contents := range input.Files {
		path, err := writeInjectedFile(runDir, input.ProjectRoot, envName, contents)
		if err != nil {
			return Result{}, err
		}
		env = append(env, fmt.Sprintf("%s=%s", envName, path))
	}

	cmd := exec.CommandContext(ctx, input.Command[0], input.Command[1:]...)
	cmd.Env = env

	// PTY path: short-circuits stdin/stdout/stderr wiring and runs its own
	// Start/Wait pair. Stderr is merged into Stdout because PTYs do not
	// preserve stream separation. Returns ErrTTYUnsupported on platforms
	// without an implementation; the caller is expected to fall back.
	if input.TTY {
		out, exit, err := executePTY(ctx, cmd, input)
		result := Result{ExitCode: exit}
		if input.Stdout == nil {
			result.Stdout = out
		}
		return result, err
	}

	// Wire stdin if provided.
	if input.Stdin != nil {
		cmd.Stdin = input.Stdin
	}

	// Wire stdout/stderr: use caller-supplied writers when present (streaming
	// path), otherwise fall back to internal buffers (legacy path).
	var stdout, stderr bytes.Buffer
	if input.Stdout != nil {
		cmd.Stdout = input.Stdout
	} else {
		cmd.Stdout = &stdout
	}
	if input.Stderr != nil {
		cmd.Stderr = input.Stderr
	} else {
		cmd.Stderr = &stderr
	}

	// Use Start+Wait instead of Run so streaming occurs: output bytes flow to
	// the writer as the child produces them, not only after the child exits.
	if err = cmd.Start(); err != nil {
		return Result{}, err
	}
	err = cmd.Wait()

	// Populate legacy fields only when internal buffers were used.
	result := Result{}
	if input.Stdout == nil {
		result.Stdout = stdout.Bytes()
	}
	if input.Stderr == nil {
		result.Stderr = stderr.Bytes()
	}

	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	return Result{}, err
}

// strippedChildEnvNames lists env vars that hold HASP-internal secrets and must
// not propagate to subprocesses. /proc/<pid>/environ and `ps ewww` make these
// readable by any same-UID observer; explicit input.Env mappings still win
// because they are appended after this filter.
var strippedChildEnvNames = map[string]struct{}{
	"HASP_SESSION_TOKEN":   {},
	"HASP_MASTER_PASSWORD": {},
}

func filterChildEnv(parent []string) []string {
	out := make([]string, 0, len(parent))
	for _, kv := range parent {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			out = append(out, kv)
			continue
		}
		if _, drop := strippedChildEnvNames[kv[:eq]]; drop {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func ensureInjectionDir(dir string, root string) error {
	current := filepath.Clean(dir)
	stop := filepath.Clean(root)
	for {
		info, err := lstatInjectionPath(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing symlinked injection dir %s", current)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat injection dir: %w", err)
		}
		if current == stop {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	if err := mkdirAllInjection(dir, 0o700); err != nil {
		return fmt.Errorf("create injection dir: %w", err)
	}
	return nil
}

// prepareRunInjectDir creates a fresh per-Execute subdir under the shared
// inject root and returns it together with a cleanup func that removes the
// whole subtree. Each call gets a random suffix so two concurrent runs never
// share a path.
func prepareRunInjectDir(injectDir string) (string, func(), error) {
	suffix, err := randomRunSuffix()
	if err != nil {
		return "", func() {}, fmt.Errorf("run dir suffix: %w", err)
	}
	runDir := filepath.Join(injectDir, runDirPrefix+suffix)
	if err := mkdirAllInjection(runDir, 0o700); err != nil {
		return "", func() {}, fmt.Errorf("create run inject dir: %w", err)
	}
	cleanup := func() { _ = removeInjectedTree(runDir) }
	return runDir, cleanup, nil
}

func randomRunSuffix() (string, error) {
	buf := make([]byte, 8)
	if _, err := randReadRunner(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// resolveCanonicalPath canonicalizes path through filepath.EvalSymlinks when
// it succeeds, falling back to filepath.Abs when EvalSymlinks fails (e.g.,
// because the path does not yet exist). This is what the writeInjectedFile
// guard uses to compare project root against the inject dir without being
// fooled by a planted symlink.
func resolveCanonicalPath(path string) (string, error) {
	if abs, err := runnerAbsPath(path); err == nil {
		if resolved, evalErr := runnerEvalSymlinks(abs); evalErr == nil {
			return resolved, nil
		}
		return abs, nil
	} else {
		return "", err
	}
}

func writeInjectedFile(injectDir string, projectRoot string, envName string, contents []byte) (string, error) {
	if projectRoot != "" {
		root, err := resolveCanonicalPath(projectRoot)
		if err != nil {
			return "", fmt.Errorf("resolve project root: %w", err)
		}
		resolvedInjectDir, err := resolveCanonicalPath(injectDir)
		if err != nil {
			return "", fmt.Errorf("resolve injection dir: %w", err)
		}
		if strings.HasPrefix(resolvedInjectDir, root+string(filepath.Separator)) || resolvedInjectDir == root {
			return "", fmt.Errorf("safe injection dir must stay outside the project root")
		}
	}

	file, err := createTempFile(injectDir, "hasp-*")
	if err != nil {
		return "", fmt.Errorf("create injected file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		_ = os.Remove(file.Name())
		return "", fmt.Errorf("chmod injected file: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		_ = os.Remove(file.Name())
		return "", fmt.Errorf("write injected file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(file.Name())
		return "", fmt.Errorf("close injected file: %w", err)
	}
	return file.Name(), nil
}

// cleanupStaleInjectedFiles reaps orphans without disturbing in-flight runs.
// Top-level `hasp-*` files (legacy flat layout from older binaries) are
// removed unconditionally; top-level `run-*` subdirs are reclaimed only after
// staleRunDirThreshold has elapsed since their creation modtime, so two
// concurrent Execute calls cannot delete each other's live credential files.
func cleanupStaleInjectedFiles(injectDir string) error {
	entries, err := readInjectionDir(injectDir)
	if err != nil {
		return fmt.Errorf("read injection dir: %w", err)
	}
	cutoff := timeNowRunner().Add(-staleRunDirThreshold)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			if !strings.HasPrefix(name, runDirPrefix) {
				continue
			}
			info, err := statInjectedPath(filepath.Join(injectDir, name))
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return fmt.Errorf("stat run inject dir: %w", err)
			}
			if info.ModTime().After(cutoff) {
				continue
			}
			if err := removeInjectedTree(filepath.Join(injectDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("cleanup stale run dir: %w", err)
			}
			continue
		}
		if !strings.HasPrefix(name, legacyInjectedFilePrefix) {
			continue
		}
		if err := removeInjectedPath(filepath.Join(injectDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cleanup stale injected file: %w", err)
		}
	}
	return nil
}
