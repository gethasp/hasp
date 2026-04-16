package paths

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type CLIConfig struct {
	HomeDir              string `json:"home_dir,omitempty"`
	AutoProtectRepos     *bool  `json:"auto_protect_repos,omitempty"`
	AutoInstallHooks     *bool  `json:"auto_install_hooks,omitempty"`
	DefaultCapturePolicy string `json:"default_capture_policy,omitempty"`
}

var (
	configReadFileFn  = os.ReadFile
	configWriteFileFn = os.WriteFile
	configMkdirAllFn  = os.MkdirAll
)

func ConfigPath() (string, error) {
	base, err := userConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "hasp-cli.json"), nil
}

func LoadConfig() (CLIConfig, error) {
	path, err := ConfigPath()
	if err != nil {
		return CLIConfig{}, err
	}
	data, err := configReadFileFn(path)
	if errors.Is(err, os.ErrNotExist) {
		return CLIConfig{}, nil
	}
	if err != nil {
		return CLIConfig{}, err
	}
	var cfg CLIConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return CLIConfig{}, err
	}
	cfg.HomeDir = strings.TrimSpace(cfg.HomeDir)
	cfg.DefaultCapturePolicy = strings.TrimSpace(cfg.DefaultCapturePolicy)
	return cfg, nil
}

func SaveConfig(cfg CLIConfig) error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}
	if err := configMkdirAllFn(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	cfg.HomeDir = strings.TrimSpace(cfg.HomeDir)
	cfg.DefaultCapturePolicy = strings.TrimSpace(cfg.DefaultCapturePolicy)
	data, _ := json.MarshalIndent(cfg, "", "  ")
	data = append(data, '\n')
	return configWriteFileFn(path, data, 0o600)
}
