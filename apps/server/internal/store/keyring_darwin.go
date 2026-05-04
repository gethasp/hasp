//go:build darwin

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type DarwinKeyring struct{}

func NewDefaultKeyring() Keyring {
	return DarwinKeyring{}
}

func (DarwinKeyring) Set(ctx context.Context, service string, account string, value string) error {
	keychainPath, err := defaultKeychainPath(ctx)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, securityBinaryPath(), "add-generic-password", "-U", "-a", account, "-s", service, "-w", value, keychainPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(strings.TrimSpace(string(out)))
	}
	return nil
}

func (DarwinKeyring) Get(service string, account string) (string, error) {
	keychainPath, err := defaultKeychainPath(context.Background())
	if err != nil {
		return "", err
	}
	cmd := exec.Command(securityBinaryPath(), "find-generic-password", "-w", "-a", account, "-s", service, keychainPath)
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New(strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func (DarwinKeyring) Delete(service string, account string) error {
	keychainPath, err := defaultKeychainPath(context.Background())
	if err != nil {
		return err
	}
	cmd := exec.Command(securityBinaryPath(), "delete-generic-password", "-a", account, "-s", service, keychainPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(strings.TrimSpace(string(out)))
	}
	return nil
}

func securityBinaryPath() string {
	if override := strings.TrimSpace(os.Getenv("HASP_TEST_SECURITY_BIN")); override != "" {
		return override
	}
	return "/usr/bin/security"
}

func ensureUsableDefaultKeychain(ctx context.Context) error {
	_, err := defaultKeychainPath(ctx)
	return err
}

func defaultKeychainPath(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, securityBinaryPath(), "default-keychain")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: macOS could not resolve the default keychain", ErrKeyringUnavailable)
	}
	path := strings.Trim(strings.TrimSpace(string(out)), "\"")
	if path == "" {
		return "", fmt.Errorf("%w: macOS returned an empty default keychain path", ErrKeyringUnavailable)
	}
	cleanPath := filepath.Clean(path)
	if _, err := os.Stat(cleanPath); err != nil {
		return "", fmt.Errorf("%w: default keychain path %s is not readable", ErrKeyringUnavailable, cleanPath)
	}
	return cleanPath, nil
}
