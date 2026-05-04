package app

import (
	"path/filepath"
	"testing"
)

type setupHarness struct {
	userHome string
}

func newSetupHarness(t *testing.T) setupHarness {
	t.Helper()
	userHome := t.TempDir()
	t.Setenv("HOME", userHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(userHome, ".config"))

	origHome := setupUserHomeDirFn
	setupUserHomeDirFn = func() (string, error) { return userHome, nil }
	t.Cleanup(func() { setupUserHomeDirFn = origHome })

	return setupHarness{userHome: userHome}
}

func (h setupHarness) stubBinary(t *testing.T, path string) {
	t.Helper()
	origLook := setupLookPathFn
	origExec := setupExecutableFn
	setupLookPathFn = func(string) (string, error) { return path, nil }
	setupExecutableFn = func() (string, error) { return path, nil }
	t.Cleanup(func() {
		setupLookPathFn = origLook
		setupExecutableFn = origExec
	})
}
