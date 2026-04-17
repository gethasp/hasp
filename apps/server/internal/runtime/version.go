package runtime

import (
	"os"
	"path/filepath"
	"strings"
)

var versionGetwd = os.Getwd
var buildVersion = ""

func Version() string {
	if value := strings.TrimSpace(os.Getenv("HASP_VERSION")); value != "" {
		return value
	}
	if value := strings.TrimSpace(buildVersion); value != "" {
		return value
	}
	dir, err := versionGetwd()
	if err != nil {
		return "0.0.0-dev"
	}
	current := dir
	for {
		versionPath := filepath.Join(current, "VERSION")
		if data, readErr := os.ReadFile(versionPath); readErr == nil {
			value := strings.TrimSpace(string(data))
			if value != "" {
				return value
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "0.0.0-dev"
}
