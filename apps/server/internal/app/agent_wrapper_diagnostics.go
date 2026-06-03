package app

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	managedWrapperConfiguredPattern = regexp.MustCompile(`(?m)^configured_hasp="([^"]+)"$`)
	legacyManagedWrapperExecPattern = regexp.MustCompile(`(?m)^exec "([^"]+)" agent mcp "([^"]+)" "\$@"$`)
	agentWrapperUserHomeDir         = os.UserHomeDir
	agentMCPProcessListFn           = listLiveAgentMCPProcesses
	agentMCPProcessListCommandFn    = func() ([]byte, error) {
		return exec.Command("ps", "-axo", "pid=,command=").Output()
	}
)

func detectManagedAgentMCPWrapperProblems() string {
	haspHome := strings.TrimSpace(os.Getenv("HASP_HOME"))
	if haspHome == "" {
		home, err := agentWrapperUserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			return ""
		}
		haspHome = filepath.Join(home, ".hasp")
	}
	wrappers, err := filepath.Glob(filepath.Join(haspHome, "bin", "hasp-agent-*"))
	if err != nil || len(wrappers) == 0 {
		return detectAgentMCPConfigEnvOverrides()
	}
	broken := []string{}
	expectedAgentBinaries := map[string]string{}
	for _, wrapper := range wrappers {
		data, err := os.ReadFile(wrapper)
		if err != nil || !strings.Contains(string(data), setupManagedAgentWrapperMarker) {
			continue
		}
		configured := managedWrapperConfiguredPath(data)
		if configured == "" {
			configured = legacyManagedWrapperConfiguredPath(data)
		}
		if configured == "" || configured == "hasp" {
			continue
		}
		if agentID := managedWrapperAgentID(wrapper); agentID != "" {
			expectedAgentBinaries[agentID] = configured
		}
		info, err := os.Stat(configured)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			broken = append(broken, filepath.Base(wrapper)+" -> "+configured)
		}
	}
	liveProcesses := detectLiveAgentMCPProcessProblems(expectedAgentBinaries)
	overrides := detectAgentMCPConfigEnvOverrides()
	if len(broken) == 0 {
		return joinAgentMCPWrapperProblems(liveProcesses, overrides)
	}
	message := "managed agent MCP wrapper points at missing or non-executable hasp: " + strings.Join(broken, ", ") + "; re-run hasp agent connect or hasp setup for the affected agent"
	return joinAgentMCPWrapperProblems(message, liveProcesses, overrides)
}

func managedWrapperConfiguredPath(data []byte) string {
	match := managedWrapperConfiguredPattern.FindSubmatch(data)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(string(match[1]))
}

func managedWrapperAgentID(wrapperPath string) string {
	name := filepath.Base(strings.TrimSpace(wrapperPath))
	if !strings.HasPrefix(name, "hasp-agent-") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(name, "hasp-agent-"))
}

func legacyManagedWrapperConfiguredPath(data []byte) string {
	match := legacyManagedWrapperExecPattern.FindSubmatch(data)
	if len(match) != 3 {
		return ""
	}
	return strings.TrimSpace(string(match[1]))
}

func detectAgentMCPConfigEnvOverrides() string {
	home, err := agentWrapperUserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	overrides := []string{}
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if data, err := os.ReadFile(codexConfig); err == nil && codexHaspEnvOverride(data) {
		overrides = append(overrides, codexConfig)
	}
	claudeConfig := filepath.Join(home, ".claude.json")
	if data, err := os.ReadFile(claudeConfig); err == nil && jsonHaspEnvOverride(data) {
		overrides = append(overrides, claudeConfig)
	}
	claudeDesktopConfig := filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	if data, err := os.ReadFile(claudeDesktopConfig); err == nil && jsonHaspEnvOverride(data) {
		overrides = append(overrides, claudeDesktopConfig)
	}
	if len(overrides) == 0 {
		return ""
	}
	return "agent MCP config sets HASP_AGENT_HASP for hasp; this can pin agents to stale binaries and shadow the managed wrapper: " + strings.Join(overrides, ", ") + "; re-run hasp agent connect for the affected agent"
}

func detectLiveAgentMCPProcessProblems(expectedAgentBinaries map[string]string) string {
	if len(expectedAgentBinaries) == 0 {
		return ""
	}
	processes, err := agentMCPProcessListFn()
	if err != nil || len(processes) == 0 {
		return ""
	}
	stale := []string{}
	for _, proc := range processes {
		expected := strings.TrimSpace(expectedAgentBinaries[proc.AgentID])
		if expected == "" || liveAgentMCPProcessMatchesExpected(proc.Binary, expected) {
			continue
		}
		stale = append(stale, "pid "+proc.PID+" "+proc.AgentID+" -> "+proc.Binary+" (expected "+expected+")")
	}
	if len(stale) == 0 {
		return ""
	}
	return "live agent MCP process is using a stale or unmanaged hasp binary: " + strings.Join(stale, ", ") + "; restart the affected agent session so its MCP connection is reopened"
}

func liveAgentMCPProcessMatchesExpected(processBinary string, expected string) bool {
	processBinary = strings.TrimSpace(processBinary)
	expected = strings.TrimSpace(expected)
	if processBinary == "" || expected == "" {
		return false
	}
	if cleanComparablePath(processBinary) == cleanComparablePath(expected) {
		return true
	}
	if filepath.IsAbs(processBinary) {
		return false
	}
	return processBinary == filepath.Base(expected)
}

type liveAgentMCPProcess struct {
	PID     string
	Binary  string
	AgentID string
}

func listLiveAgentMCPProcesses() ([]liveAgentMCPProcess, error) {
	out, err := agentMCPProcessListCommandFn()
	if err != nil {
		return nil, err
	}
	processes := []liveAgentMCPProcess{}
	for _, line := range bytes.Split(out, []byte("\n")) {
		if proc := parseLiveAgentMCPProcessLine(string(line)); proc.PID != "" {
			processes = append(processes, proc)
		}
	}
	return processes, nil
}

func parseLiveAgentMCPProcessLine(line string) liveAgentMCPProcess {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 4 {
		return liveAgentMCPProcess{}
	}
	for i := 2; i+2 < len(fields); i++ {
		if fields[i] == "agent" && fields[i+1] == "mcp" {
			return liveAgentMCPProcess{
				PID:     fields[0],
				Binary:  strings.Join(fields[1:i], " "),
				AgentID: fields[i+2],
			}
		}
	}
	return liveAgentMCPProcess{}
}

func joinAgentMCPWrapperProblems(parts ...string) string {
	kept := []string{}
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			kept = append(kept, trimmed)
		}
	}
	return strings.Join(kept, "; ")
}

func codexHaspEnvOverride(data []byte) bool {
	lines := strings.Split(string(data), "\n")
	inHaspEnv := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inHaspEnv = trimmed == "[mcp_servers.hasp.env]"
			continue
		}
		if inHaspEnv && tomlKeyLine(trimmed, "HASP_AGENT_HASP") {
			return true
		}
	}
	return false
}

func tomlKeyLine(line string, key string) bool {
	if !strings.HasPrefix(line, key) {
		return false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, key))
	return strings.HasPrefix(rest, "=")
}

func jsonHaspEnvOverride(data []byte) bool {
	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		return false
	}
	return jsonValueHaspEnvOverride(payload)
}

func jsonValueHaspEnvOverride(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		if servers, ok := typed["mcpServers"].(map[string]any); ok {
			if hasp, ok := servers["hasp"].(map[string]any); ok {
				if env, ok := hasp["env"].(map[string]any); ok {
					if _, ok := env["HASP_AGENT_HASP"]; ok {
						return true
					}
				}
			}
		}
		if hasp, ok := typed["hasp"].(map[string]any); ok {
			if env, ok := hasp["env"].(map[string]any); ok {
				if _, ok := env["HASP_AGENT_HASP"]; ok {
					return true
				}
			}
		}
		for _, child := range typed {
			if jsonValueHaspEnvOverride(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if jsonValueHaspEnvOverride(child) {
				return true
			}
		}
	}
	return false
}
