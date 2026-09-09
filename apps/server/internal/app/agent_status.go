package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
)

// Inspect installation without starting the client, opening the vault, or
// creating a session. Only the current process can attest its own lineage.
func agentStatus(ctx context.Context, id string) (map[string]any, error) {
	specs, err := selectSetupAgents(setupSupportedAgents(), []string{id})
	if err != nil {
		return nil, err
	}
	spec := specs[0]
	paths, err := appResolvePathsFn()
	if err != nil {
		return nil, err
	}
	wrapper, err := setupAgentWrapperPath(paths.HomeDir, id)
	if err != nil {
		return nil, err
	}
	binary, _ := setupLookPathFn(setupAgentBinary(id))
	configState, detail := inspectAgentConfig(spec, paths.HomeDir, wrapper)
	wrapperState := "missing"
	if info, err := os.Lstat(wrapper); err == nil {
		switch {
		case !info.Mode().IsRegular():
			wrapperState = "not_regular"
		case info.Mode()&0o111 == 0:
			wrapperState = "not_executable"
		default:
			data, err := os.ReadFile(wrapper)
			switch {
			case err != nil:
				wrapperState = "unreadable"
			case agentWrapperMatchesCurrentBinary(data, paths.HomeDir, id):
				wrapperState = "current"
			default:
				wrapperState = "unverified"
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		wrapperState = "unreadable"
	}
	result := map[string]any{
		"agent_id": id, "client_installed": binary != "", "client_binary": binary,
		"config_path": spec.ConfigPath(""), "configuration": configState, "configuration_detail": detail,
		"wrapper_path": wrapper, "wrapper": wrapperState,
		"connection": "not_observed", "connection_hint": "Call hasp_status from the client's HASP tools to verify that transport.",
		"process_scope": "current_command_and_ancestors", "process_protection": "not_observed",
		"project_plaintext_policy": "not_checked", "plaintext_grant": "not_checked",
		"repair":           "hasp agent connect " + id,
		"protected_launch": shellJoinArgs([]string{"hasp", "agent", "launch", id, "--", setupAgentBinary(id)}),
	}
	result["configured"] = configState == "current" && wrapperState == "current"
	probeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if session, _, ok, err := secretSessionFromProcessTree(probeCtx); err != nil {
		result["process_protection"] = "unavailable"
	} else if ok && session.AgentSafe {
		result["process_protection"] = "daemon_process_tree"
		result["session_id"] = session.ID
		result["session_project_root"] = session.ProjectRoot
		result["session_consumer"] = session.ConsumerName
		return result, nil
	}
	if session, _, ok, err := secretSessionFromEnv(probeCtx); err != nil {
		result["session_state"] = "unavailable"
	} else if ok && session.AgentSafe {
		result["process_protection"] = "daemon_session_environment"
		result["session_id"] = session.ID
		result["session_project_root"] = session.ProjectRoot
		result["session_consumer"] = session.ConsumerName
		return result, nil
	}
	if envTruthy(secrettypes.EnvAgentSafeMode) {
		result["process_protection"] = "environment_guard"
	}
	return result, nil
}

func agentWrapperMatchesCurrentBinary(data []byte, haspHome, id string) bool {
	current := setupHaspCommandPath()
	if bytes.Equal(data, setupAgentWrapperContent(haspHome, current, id)) {
		return true
	}
	// The client may invoke a symlink to the configured executable. Compare
	// file identity before declaring that otherwise identical wrapper stale.
	configured := managedWrapperConfiguredPath(data)
	installed, installedErr := os.Stat(configured)
	running, runningErr := os.Stat(current)
	return installedErr == nil && runningErr == nil && os.SameFile(installed, running) && bytes.Equal(data, setupAgentWrapperContent(haspHome, configured, id))
}

func inspectAgentConfig(spec setupAgentSpec, haspHome, wrapper string) (string, string) {
	if spec.Format == "manual" {
		return "manual", "Client wiring must be checked in the client."
	}
	path := spec.ConfigPath("")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "missing", "Client configuration does not exist."
	}
	if err != nil {
		return "unreadable", "Client configuration could not be read."
	}
	if spec.Format == "toml" {
		// Exact managed syntax can be attested without accepting arbitrary TOML.
		// Other valid configurations remain unverified, never reported broken.
		updated := upsertCodexMCPServerConfig(data, haspHome, wrapper, spec.ID)
		if agentConfigNonemptyLines(updated) == agentConfigNonemptyLines(string(data)) {
			return "current", "Managed MCP entry is present."
		}
		return "unverified", "Configuration differs from the managed MCP entry."
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil || config == nil {
		return "unverified", "Configuration is not a JSON object; custom configuration must be checked in the client."
	}
	if spec.Format == "pi-package" {
		packages, _ := config["packages"].([]any)
		found := false
		for _, entry := range packages {
			if entry == setupPiPackagePath(haspHome) {
				found = true
			}
		}
		if !found {
			return "missing", "Managed Pi package is absent from settings."
		}
		extension, err := os.ReadFile(filepath.Join(setupPiPackagePath(haspHome), "extensions", "hasp", "index.js"))
		if err != nil || !bytes.Equal(extension, setupPiExtensionContent(wrapper, spec.ID)) {
			return "outdated", "Managed Pi extension is missing or differs from this HASP build."
		}
		return "current", "Managed package and persistent MCP bridge are present."
	}
	if spec.Format == "opencode-json" {
		servers, _ := config["mcp"].(map[string]any)
		entry, _ := servers["hasp"].(map[string]any)
		if entry == nil {
			return "missing", "HASP MCP entry is absent."
		}
		if entry["enabled"] == false {
			return "disabled", "HASP MCP entry is disabled."
		}
		command, _ := entry["command"].([]any)
		if len(command) != 1 || command[0] != wrapper || entry["type"] != "local" || entry["enabled"] != true || len(entry) != 3 {
			return "unverified", "Configuration differs from the managed OpenCode 1.x MCP entry."
		}
		return "current", "Managed OpenCode 1.x MCP entry is present; client overrides still require a live check."
	}
	servers, _ := config["mcpServers"].(map[string]any)
	entry, _ := servers["hasp"].(map[string]any)
	if entry == nil {
		return "missing", "HASP MCP entry is absent."
	}
	if entry["disabled"] == true || entry["enabled"] == false {
		return "disabled", "HASP MCP entry is disabled."
	}
	if entry["command"] != wrapper || len(entry) != 1 {
		return "unverified", "Configuration differs from the managed MCP entry."
	}
	return "current", "Managed MCP entry is present."
}

func agentConfigNonemptyLines(data string) string {
	lines := []string{}
	for _, line := range strings.Split(data, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}
