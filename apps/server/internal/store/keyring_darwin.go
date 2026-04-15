//go:build darwin

package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

type DarwinKeyring struct{}

func NewDefaultKeyring() Keyring {
	return DarwinKeyring{}
}

func (DarwinKeyring) Set(ctx context.Context, service string, account string, value string) error {
	cmd := exec.CommandContext(ctx, securityBinaryPath(), "add-generic-password", "-U", "-a", account, "-s", service, "-w", value)
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(strings.TrimSpace(string(out)))
	}
	return nil
}

func (DarwinKeyring) Get(service string, account string) (string, error) {
	cmd := exec.Command(securityBinaryPath(), "find-generic-password", "-w", "-a", account, "-s", service)
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New(strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func (DarwinKeyring) Delete(service string, account string) error {
	cmd := exec.Command(securityBinaryPath(), "delete-generic-password", "-a", account, "-s", service)
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
