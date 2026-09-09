package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func setupOpenCodeConfigPath(home string) string {
	if configured := strings.TrimSpace(os.Getenv("OPENCODE_CONFIG")); configured != "" {
		return configured
	}
	configDir := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if configDir == "" {
		configDir = filepath.Join(home, ".config")
	}
	path := filepath.Join(configDir, "opencode", "opencode.json")
	// Do not create a competing JSON file when the user already chose JSONC.
	commented := path + "c"
	if _, err := os.Lstat(commented); err == nil {
		return commented
	}
	return path
}

func updateOpenCodeMCPConfig(existing []byte, wrapper string, remove bool) ([]byte, error) {
	config := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := json.Unmarshal(existing, &config); err != nil {
			return nil, errors.New("automatic setup requires a JSON object without comments or trailing commas; existing JSONC was left unchanged. Add the local mcp.hasp entry from docs/agent-profiles/opencode.md manually, or select a separate JSON file with OPENCODE_CONFIG for both hasp agent connect opencode and opencode")
		}
	}
	if config == nil {
		return nil, errors.New("OpenCode configuration must be an object")
	}
	servers := map[string]any{}
	if raw, ok := config["mcp"]; ok {
		var valid bool
		servers, valid = raw.(map[string]any)
		if !valid {
			return nil, fmt.Errorf("existing mcp value is not an object")
		}
	}
	if _, version2 := servers["servers"]; version2 {
		return nil, errors.New("mcp.servers configuration is not the OpenCode 1.x format supported by this adapter; existing configuration was left unchanged")
	}
	if remove {
		delete(servers, "hasp")
	} else {
		servers["hasp"] = map[string]any{"type": "local", "command": []string{wrapper}, "enabled": true}
	}
	config["mcp"] = servers
	data, err := json.MarshalIndent(config, "", "  ")
	return append(data, '\n'), err
}
