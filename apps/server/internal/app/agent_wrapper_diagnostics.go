package app

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	managedWrapperConfiguredPattern = regexp.MustCompile(`(?m)^configured_hasp="([^"]+)"$`)
	legacyManagedWrapperExecPattern = regexp.MustCompile(`(?m)^exec "([^"]+)" agent mcp "([^"]+)" "\$@"$`)
	agentWrapperUserHomeDir         = os.UserHomeDir
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
		return ""
	}
	broken := []string{}
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
		info, err := os.Stat(configured)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			broken = append(broken, filepath.Base(wrapper)+" -> "+configured)
		}
	}
	if len(broken) == 0 {
		return ""
	}
	return "managed agent MCP wrapper points at missing or non-executable hasp: " + strings.Join(broken, ", ") + "; re-run hasp agent connect or hasp setup for the affected agent"
}

func managedWrapperConfiguredPath(data []byte) string {
	match := managedWrapperConfiguredPattern.FindSubmatch(data)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(string(match[1]))
}

func legacyManagedWrapperConfiguredPath(data []byte) string {
	match := legacyManagedWrapperExecPattern.FindSubmatch(data)
	if len(match) != 3 {
		return ""
	}
	return strings.TrimSpace(string(match[1]))
}
