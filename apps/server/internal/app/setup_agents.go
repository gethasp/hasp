package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type setupAgentSpec struct {
	ID         string
	Label      string
	Format     string
	ConfigPath func(home string) string
}

type setupAgentOutcome struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	ConfigPath string `json:"config_path"`
	BackupPath string `json:"backup_path,omitempty"`
	Changed    bool   `json:"changed"`
}

// Agent setup flow:
//
//	selected agent -> install managed wrapper -> upsert client config
//	config entry    -> wrapper script         -> `hasp agent mcp <agent-id>`
//
// Format "manual" agents have no canonical client-config file; HASP installs
// the wrapper and saves the consumer, but the user wires the agent's MCP
// surface to the wrapper themselves per docs/agent-profiles/<id>.md.
//
// Format "pi-package" agents use Pi's package/extension surface instead of a
// native MCP config file. HASP writes a generated package under HASP_HOME and
// registers that package path in Pi's settings.json.
func setupSupportedAgents() []setupAgentSpec {
	home, _ := setupUserHomeDirFn()
	return []setupAgentSpec{
		{
			ID:     "codex-cli",
			Label:  "Codex CLI",
			Format: "toml",
			ConfigPath: func(_ string) string {
				return filepath.Join(home, ".codex", "config.toml")
			},
		},
		{
			ID:     "claude-code",
			Label:  "Claude Code",
			Format: "json",
			ConfigPath: func(_ string) string {
				return filepath.Join(home, ".claude.json")
			},
		},
		{
			ID:     "cursor",
			Label:  "Cursor",
			Format: "json",
			ConfigPath: func(_ string) string {
				return filepath.Join(home, ".cursor", "mcp.json")
			},
		},
		{
			ID:     "pi",
			Label:  "Pi",
			Format: "pi-package",
			ConfigPath: func(_ string) string {
				return filepath.Join(setupPiAgentConfigDir(home), "settings.json")
			},
		},
		{
			ID:         "aider",
			Label:      "Aider",
			Format:     "manual",
			ConfigPath: func(_ string) string { return "" },
		},
		{
			ID:         "hermes",
			Label:      "Hermes",
			Format:     "manual",
			ConfigPath: func(_ string) string { return "" },
		},
		{
			ID:         "openclaw",
			Label:      "OpenClaw",
			Format:     "manual",
			ConfigPath: func(_ string) string { return "" },
		},
	}
}

func detectSetupAgents(supported []setupAgentSpec) []setupAgentSpec {
	detected := []setupAgentSpec{}
	for _, spec := range supported {
		if _, err := setupLookPathFn(setupAgentBinary(spec.ID)); err == nil {
			detected = append(detected, spec)
			continue
		}
		if _, err := os.Stat(spec.ConfigPath("")); err == nil {
			detected = append(detected, spec)
		}
	}
	return detected
}

func selectSetupAgents(supported []setupAgentSpec, ids []string) ([]setupAgentSpec, error) {
	selected := []setupAgentSpec{}
	seen := map[string]struct{}{}
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		idx := slices.IndexFunc(supported, func(spec setupAgentSpec) bool { return spec.ID == id })
		if idx < 0 {
			return nil, fmt.Errorf("unsupported setup agent %q", id)
		}
		selected = append(selected, supported[idx])
		seen[id] = struct{}{}
	}
	return selected, nil
}

func setupAgentBinary(id string) string {
	switch id {
	case "codex-cli":
		return "codex"
	case "claude-code":
		return "claude"
	case "cursor":
		return "cursor"
	case "pi":
		return "pi"
	case "aider":
		return "aider"
	case "hermes":
		return "hermes"
	case "openclaw":
		return "openclaw"
	default:
		return id
	}
}

func setupAnyExistingAgentConfig(agents []setupAgentSpec) bool {
	for _, agent := range agents {
		if _, err := os.Lstat(agent.ConfigPath("")); err == nil {
			return true
		}
	}
	return false
}

func setupWriteAgentConfigs(agents []setupAgentSpec, haspHome string) ([]setupAgentOutcome, error) {
	outcomes := make([]setupAgentOutcome, 0, len(agents))
	for _, agent := range agents {
		wrapperPath, err := setupInstallAgentWrapper(haspHome, setupHaspCommandPath(), agent.ID)
		if err != nil {
			return nil, err
		}
		if agent.Format == "pi-package" {
			packagePath, err := setupInstallPiPackage(haspHome, wrapperPath, agent.ID)
			if err != nil {
				return nil, err
			}
			path := agent.ConfigPath("")
			info, err := os.Lstat(path)
			if err == nil && info.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("agent config path is a symlink: %s", path)
			}
			var existing []byte
			if err == nil {
				existing, err = setupReadFileFn(path)
				if err != nil {
					return nil, err
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			updated, err := upsertPiSettingsPackageConfig(existing, packagePath)
			if err != nil {
				return nil, err
			}
			backupPath, changed, err := setupAtomicWrite(path, existing, updated)
			if err != nil {
				return nil, err
			}
			outcomes = append(outcomes, setupAgentOutcome{
				ID:         agent.ID,
				Label:      agent.Label,
				ConfigPath: path,
				BackupPath: backupPath,
				Changed:    changed,
			})
			continue
		}
		if agent.Format == "manual" {
			outcomes = append(outcomes, setupAgentOutcome{
				ID:         agent.ID,
				Label:      agent.Label,
				ConfigPath: wrapperPath,
				BackupPath: "",
				Changed:    false,
			})
			continue
		}
		path := agent.ConfigPath("")
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("agent config path is a symlink: %s", path)
		}
		var existing []byte
		if err == nil {
			existing, err = setupReadFileFn(path)
			if err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		var updated []byte
		switch agent.Format {
		case "toml":
			updated = []byte(upsertCodexMCPServerConfig(existing, haspHome, wrapperPath, agent.ID))
		case "json":
			updated, err = upsertJSONMCPServerConfig(existing, haspHome, wrapperPath, agent.ID)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported setup config format %q", agent.Format)
		}

		backupPath, changed, err := setupAtomicWrite(path, existing, updated)
		if err != nil {
			return nil, err
		}
		outcomes = append(outcomes, setupAgentOutcome{
			ID:         agent.ID,
			Label:      agent.Label,
			ConfigPath: path,
			BackupPath: backupPath,
			Changed:    changed,
		})
	}
	return outcomes, nil
}

func setupHaspCommandPath() string {
	if path, err := setupLookPathFn("hasp"); err == nil && strings.TrimSpace(path) != "" {
		return path
	}
	if path, err := setupExecutableFn(); err == nil && strings.TrimSpace(path) != "" && filepath.Base(path) == "hasp" {
		return path
	}
	return "hasp"
}

const setupManagedAgentWrapperMarker = "# hasp-managed agent wrapper"

func setupAgentWrapperPath(haspHome string, agentID string) (string, error) {
	haspHome = strings.TrimSpace(haspHome)
	if haspHome == "" {
		return "", errors.New("hasp home is required")
	}
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return "", errors.New("agent id is required")
	}
	return filepath.Join(haspHome, "bin", "hasp-agent-"+agentID), nil
}

func setupInstallAgentWrapper(haspHome string, commandPath string, agentID string) (string, error) {
	wrapperPath, err := setupAgentWrapperPath(haspHome, agentID)
	if err != nil {
		return "", err
	}
	content := setupAgentWrapperContent(haspHome, commandPath, agentID)
	existing, err := setupReadFileFn(wrapperPath)
	if err == nil {
		if !bytes.Contains(existing, []byte(setupManagedAgentWrapperMarker)) {
			return "", fmt.Errorf("agent wrapper path %q already exists and is not managed by hasp", wrapperPath)
		}
		if bytes.Equal(existing, content) {
			return wrapperPath, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := setupMkdirAllFn(filepath.Dir(wrapperPath), 0o700); err != nil {
		return "", err
	}
	if err := setupWriteFileFn(wrapperPath, content, 0o700); err != nil {
		return "", err
	}
	return wrapperPath, nil
}

func setupAgentWrapperContent(haspHome string, commandPath string, agentID string) []byte {
	return []byte(
		"#!/usr/bin/env bash\n" +
			setupManagedAgentWrapperMarker + "\n" +
			"set -euo pipefail\n" +
			"export HASP_HOME=" + strconvQuote(haspHome) + "\n" +
			"configured_hasp=" + strconvQuote(commandPath) + "\n" +
			"find_hasp() {\n" +
			"  if [[ -n \"${HASP_AGENT_HASP:-}\" && -x \"${HASP_AGENT_HASP}\" ]]; then\n" +
			"    printf '%s\\n' \"${HASP_AGENT_HASP}\"\n" +
			"    return 0\n" +
			"  fi\n" +
			"  if [[ -x \"$configured_hasp\" ]]; then\n" +
			"    printf '%s\\n' \"$configured_hasp\"\n" +
			"    return 0\n" +
			"  fi\n" +
			"  local resolved=\"\"\n" +
			"  if resolved=\"$(command -v hasp 2>/dev/null)\" && [[ -n \"$resolved\" && -x \"$resolved\" ]]; then\n" +
			"    printf '%s\\n' \"$resolved\"\n" +
			"    return 0\n" +
			"  fi\n" +
			"  local candidate=\"\"\n" +
			"  for candidate in /opt/homebrew/bin/hasp /opt/homebrew/opt/hasp/bin/hasp /usr/local/bin/hasp /usr/local/opt/hasp/bin/hasp; do\n" +
			"    if [[ -x \"$candidate\" ]]; then\n" +
			"      printf '%s\\n' \"$candidate\"\n" +
			"      return 0\n" +
			"    fi\n" +
			"  done\n" +
			"  return 1\n" +
			"}\n" +
			"hasp_command=\"$(find_hasp)\" || {\n" +
			"  printf 'HASP agent wrapper could not find a runnable hasp binary. Re-run hasp agent connect " + agentID + " or set HASP_AGENT_HASP.\\n' >&2\n" +
			"  exit 127\n" +
			"}\n" +
			"exec \"$hasp_command\" agent mcp " + strconvQuote(agentID) + " \"$@\"\n",
	)
}

func setupPiPackagePath(haspHome string) string {
	return filepath.Join(haspHome, "pi-package")
}

func setupPiAgentConfigDir(home string) string {
	if configured := strings.TrimSpace(os.Getenv("PI_CODING_AGENT_DIR")); configured != "" {
		if configured == "~" {
			return home
		}
		if strings.HasPrefix(configured, "~/") {
			return filepath.Join(home, strings.TrimPrefix(configured, "~/"))
		}
		return configured
	}
	return filepath.Join(home, ".pi", "agent")
}

func setupInstallPiPackage(haspHome string, wrapperPath string, agentID string) (string, error) {
	packagePath := setupPiPackagePath(haspHome)
	extensionDir := filepath.Join(packagePath, "extensions", "hasp")
	if err := setupMkdirAllFn(extensionDir, 0o700); err != nil {
		return "", err
	}
	packageJSON := []byte(`{
  "name": "hasp-pi",
  "version": "1.0.0",
  "type": "module",
  "keywords": ["pi-package"],
  "pi": {
    "extensions": ["./extensions"]
  }
}
`)
	if err := setupWriteFileFn(filepath.Join(packagePath, "package.json"), packageJSON, 0o600); err != nil {
		return "", err
	}
	if err := setupWriteFileFn(filepath.Join(extensionDir, "index.js"), setupPiExtensionContent(wrapperPath, agentID), 0o600); err != nil {
		return "", err
	}
	return packagePath, nil
}

func setupPiExtensionContent(wrapperPath string, agentID string) []byte {
	return []byte(`import { spawnSync } from "node:child_process";

const HASP_MCP_COMMAND = ` + strconvQuote(wrapperPath) + `;
const HASP_AGENT_ID = ` + strconvQuote(agentID) + `;

function runMCP(requests, cwd) {
  const input = requests.map((request) => JSON.stringify(request)).join("\n") + "\n";
  const result = spawnSync(HASP_MCP_COMMAND, [], {
    input,
    encoding: "utf8",
    cwd: cwd || process.cwd(),
    env: process.env,
    maxBuffer: 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || ` + strconvQuote("hasp MCP command failed") + `).trim());
  }
  const lines = result.stdout.split(/\r?\n/).filter((line) => line.trim() !== "");
  return lines.map((line) => JSON.parse(line));
}

function listTools(ctx) {
  const responses = runMCP([
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "pi", version: "1" } } },
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
  ], ctx?.cwd);
  const list = responses[1]?.result?.tools;
  if (!Array.isArray(list)) throw new Error("HASP MCP tools/list returned no tools array");
  return list;
}

function callTool(name, params, ctx) {
  const responses = runMCP([
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "pi", version: "1" } } },
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name, arguments: params || {} } },
  ], ctx?.cwd);
  const response = responses[1];
  if (response?.error) throw new Error(response.error.message || JSON.stringify(response.error));
  return response?.result ?? {};
}

function textContent(result) {
  if (Array.isArray(result?.content) && result.content.length > 0) return result.content;
  return [{ type: "text", text: JSON.stringify(result, null, 2) }];
}

export default function haspPiExtension(pi) {
  let tools = [];
  try {
    tools = listTools();
  } catch (error) {
    pi.registerTool({
      name: "hasp_status",
      label: "HASP Status",
      description: "Report why the HASP Pi extension could not load MCP tools.",
      parameters: { type: "object", properties: {}, additionalProperties: false },
      async execute() {
        return {
          content: [{ type: "text", text: ` + "`HASP Pi profile ${HASP_AGENT_ID} could not load MCP tools: ${error instanceof Error ? error.message : String(error)}`" + ` }],
          details: { ok: false, error: error instanceof Error ? error.message : String(error) },
        };
      },
    });
    return;
  }

  for (const tool of tools) {
    pi.registerTool({
      name: tool.name,
      label: tool.title || tool.name,
      description: tool.description || ` + "`HASP MCP tool ${tool.name}`" + `,
      parameters: tool.inputSchema || { type: "object", properties: {}, additionalProperties: true },
      async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
        const result = callTool(tool.name, params, ctx);
        return { content: textContent(result), details: result };
      },
    });
  }
}
`)
}

func upsertCodexMCPServerConfig(existing []byte, haspHome string, commandPath string, agentID string) string {
	blockLines := []string{
		"[mcp_servers.hasp]",
		"command = " + strconvQuote(commandPath),
	}
	block := strings.Join(blockLines, "\n") + "\n"
	content := strings.TrimRight(string(existing), "\n")
	if content == "" {
		return block
	}
	lines := strings.Split(content, "\n")
	out := []string{}
	skipping := false
	inserted := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[mcp_servers.hasp]" || trimmed == "[mcp_servers.hasp.env]" {
			if !inserted {
				out = append(out, strings.TrimRight(block, "\n"))
				inserted = true
			}
			skipping = true
			continue
		}
		if skipping && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			skipping = false
		}
		if skipping {
			continue
		}
		out = append(out, line)
	}
	if !inserted {
		out = append(out, "", strings.TrimRight(block, "\n"))
	}
	return strings.TrimLeft(strings.Join(out, "\n"), "\n") + "\n"
}

func upsertJSONMCPServerConfig(existing []byte, haspHome string, commandPath string, agentID string) ([]byte, error) {
	config := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := json.Unmarshal(existing, &config); err != nil {
			return nil, err
		}
	}
	mcpServers := map[string]any{}
	if existingServers, ok := config["mcpServers"]; ok {
		typed, ok := existingServers.(map[string]any)
		if !ok {
			return nil, errors.New("existing mcpServers value is not an object")
		}
		mcpServers = typed
	}
	serverConfig := map[string]any{
		"command": commandPath,
	}
	mcpServers["hasp"] = serverConfig
	config["mcpServers"] = mcpServers
	data, _ := json.MarshalIndent(config, "", "  ")
	return append(data, '\n'), nil
}

func upsertPiSettingsPackageConfig(existing []byte, packagePath string) ([]byte, error) {
	config := map[string]any{}
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := json.Unmarshal(existing, &config); err != nil {
			return nil, err
		}
	}
	packages := []any{}
	if existingPackages, ok := config["packages"]; ok {
		typed, ok := existingPackages.([]any)
		if !ok {
			return nil, errors.New("existing packages value is not an array")
		}
		packages = typed
	}
	found := false
	for _, entry := range packages {
		if value, ok := entry.(string); ok && value == packagePath {
			found = true
			break
		}
	}
	if !found {
		packages = append(packages, packagePath)
	}
	config["packages"] = packages
	data, _ := json.MarshalIndent(config, "", "  ")
	return append(data, '\n'), nil
}

func removeAgentConsumerConfig(spec setupAgentSpec, path string) error {
	if spec.Format == "manual" {
		return nil
	}
	existing, err := setupReadFileFn(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var updated []byte
	switch spec.Format {
	case "toml":
		updated = []byte(removeCodexMCPServerConfig(existing))
	case "json":
		updated, err = removeJSONMCPServerConfig(existing)
		if err != nil {
			return err
		}
	case "pi-package":
		resolved, resolveErr := appResolvePathsFn()
		if resolveErr != nil {
			return resolveErr
		}
		updated, err = removePiSettingsPackageConfig(existing, setupPiPackagePath(resolved.HomeDir))
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported setup config format %q", spec.Format)
	}
	_, _, err = agentAtomicWriteFn(path, existing, updated)
	return err
}

func removeCodexMCPServerConfig(existing []byte) string {
	content := strings.TrimRight(string(existing), "\n")
	if content == "" {
		return ""
	}
	lines := strings.Split(content, "\n")
	out := []string{}
	skipping := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[mcp_servers.hasp]" || trimmed == "[mcp_servers.hasp.env]" {
			skipping = true
			continue
		}
		if skipping && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			skipping = false
		}
		if skipping {
			continue
		}
		out = append(out, line)
	}
	return strings.TrimSpace(strings.Join(out, "\n")) + "\n"
}

func removeJSONMCPServerConfig(existing []byte) ([]byte, error) {
	if len(bytes.TrimSpace(existing)) == 0 {
		return []byte("{}\n"), nil
	}
	config := map[string]any{}
	if err := json.Unmarshal(existing, &config); err != nil {
		return nil, err
	}
	existingServers, ok := config["mcpServers"]
	if !ok {
		data, _ := json.MarshalIndent(config, "", "  ")
		return append(data, '\n'), nil
	}
	typed, ok := existingServers.(map[string]any)
	if !ok {
		return nil, errors.New("existing mcpServers value is not an object")
	}
	delete(typed, "hasp")
	config["mcpServers"] = typed
	data, _ := json.MarshalIndent(config, "", "  ")
	return append(data, '\n'), nil
}

func removePiSettingsPackageConfig(existing []byte, packagePath string) ([]byte, error) {
	if len(bytes.TrimSpace(existing)) == 0 {
		return []byte("{}\n"), nil
	}
	config := map[string]any{}
	if err := json.Unmarshal(existing, &config); err != nil {
		return nil, err
	}
	existingPackages, ok := config["packages"]
	if !ok {
		data, _ := json.MarshalIndent(config, "", "  ")
		return append(data, '\n'), nil
	}
	typed, ok := existingPackages.([]any)
	if !ok {
		return nil, errors.New("existing packages value is not an array")
	}
	packages := make([]any, 0, len(typed))
	for _, entry := range typed {
		if value, ok := entry.(string); ok && value == packagePath {
			continue
		}
		packages = append(packages, entry)
	}
	config["packages"] = packages
	data, _ := json.MarshalIndent(config, "", "  ")
	return append(data, '\n'), nil
}
