package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

type injectedTempFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Close() error
}

var (
	resolveRunnerPaths = paths.Resolve
	runnerAbsPath      = filepath.Abs
	lstatInjectionPath = os.Lstat
	mkdirAllInjection  = os.MkdirAll
	readInjectionDir   = os.ReadDir
	removeInjectedPath = os.Remove
	createTempFile     = func(dir string, pattern string) (injectedTempFile, error) {
		return os.CreateTemp(dir, pattern)
	}
)

type Input struct {
	ProjectRoot string
	Command     []string
	Env         map[string]string
	Files       map[string][]byte
}

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

	env := os.Environ()
	for name, value := range input.Env {
		env = append(env, fmt.Sprintf("%s=%s", name, value))
	}

	var cleanup []string
	defer func() {
		for _, path := range cleanup {
			_ = os.Remove(path)
		}
	}()
	for envName, contents := range input.Files {
		path, err := writeInjectedFile(injectDir, input.ProjectRoot, envName, contents)
		if err != nil {
			return Result{}, err
		}
		cleanup = append(cleanup, path)
		env = append(env, fmt.Sprintf("%s=%s", envName, path))
	}

	cmd := exec.CommandContext(ctx, input.Command[0], input.Command[1:]...)
	cmd.Env = env
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	result := Result{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
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

func writeInjectedFile(injectDir string, projectRoot string, envName string, contents []byte) (string, error) {
	if projectRoot != "" {
		root, err := runnerAbsPath(projectRoot)
		if err != nil {
			return "", fmt.Errorf("resolve project root: %w", err)
		}
		resolvedInjectDir, err := runnerAbsPath(injectDir)
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

func cleanupStaleInjectedFiles(injectDir string) error {
	entries, err := readInjectionDir(injectDir)
	if err != nil {
		return fmt.Errorf("read injection dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "hasp-") {
			continue
		}
		if err := removeInjectedPath(filepath.Join(injectDir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cleanup stale injected file: %w", err)
		}
	}
	return nil
}
