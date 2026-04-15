package profiles

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const envProfilesDir = "HASP_PROFILES_DIR"

func CatalogDir() (string, error) {
	if override := strings.TrimSpace(os.Getenv(envProfilesDir)); override != "" {
		info, err := os.Stat(override)
		if err != nil {
			return "", fmt.Errorf("stat %s: %w", override, err)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("%s is not a directory", override)
		}
		return override, nil
	}
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "apps", "server", "profiles")
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("profiles directory not found")
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	return dir, nil
}

func repoRoot() (string, error) {
	root, err := repoRootWith(os.Getwd)
	if err == nil {
		return root, nil
	}
	if override := strings.TrimSpace(os.Getenv(envProfilesDir)); override != "" {
		repoLikeRoot := filepath.Dir(filepath.Dir(filepath.Dir(override)))
		if _, statErr := os.Stat(filepath.Join(repoLikeRoot, "VERSION")); statErr == nil {
			return repoLikeRoot, nil
		}
	}
	return "", err
}

func repoRootWith(getwd func() (string, error)) (string, error) {
	cwd, err := getwd()
	if err != nil {
		return "", err
	}
	if root, ok := walkToVersion(cwd); ok {
		return root, nil
	}
	return "", fmt.Errorf("repo root not found")
}

func walkToVersion(start string) (string, bool) {
	current := start
	for {
		if _, err := os.Stat(filepath.Join(current, "VERSION")); err == nil {
			return current, true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		current = parent
	}
}

func ResolveRepoPath(rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return rel, nil
	}
	if root, err := repoRoot(); err == nil {
		candidate := filepath.Join(root, rel)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	if dir, err := CatalogDir(); err == nil {
		repoLikeRoot := filepath.Dir(filepath.Dir(filepath.Dir(dir)))
		candidate := filepath.Join(repoLikeRoot, rel)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("path %s not found", rel)
}

func findBenchmarkFunction(pkg string, fnName string) bool {
	root, err := repoRoot()
	if err != nil {
		return false
	}
	pattern := filepath.Join(root, "apps", "server", strings.TrimPrefix(pkg, "./"), "*_test.go")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return false
	}
	for _, match := range matches {
		data, err := os.ReadFile(match)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "func "+fnName+"(") {
			return true
		}
	}
	return false
}

func findEvalTest(testName string) bool {
	root, err := repoRoot()
	if err != nil {
		return false
	}
	pattern := filepath.Join(root, "apps", "server", "internal", "evals", "*_test.go")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return false
	}
	for _, match := range matches {
		data, err := os.ReadFile(match)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "func "+testName+"(") {
			return true
		}
	}
	return false
}
