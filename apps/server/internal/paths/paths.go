package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	EnvHome   = "HASP_HOME"
	EnvSocket = "HASP_SOCKET"
)

var userConfigDir = os.UserConfigDir

type Paths struct {
	HomeDir     string
	RuntimeDir  string
	SocketPath  string
	PidFilePath string
	StatePath   string
	AuditPath   string
}

func Resolve() (Paths, error) {
	home := os.Getenv(EnvHome)
	if home == "" {
		cfg, err := LoadConfig()
		if err != nil {
			return Paths{}, fmt.Errorf("load cli config: %w", err)
		}
		home = strings.TrimSpace(cfg.HomeDir)
	}
	if home == "" {
		base, err := userConfigDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve user config dir: %w", err)
		}
		home = filepath.Join(base, "hasp")
	}

	runtimeDir := filepath.Join(home, "runtime")
	socketPath := os.Getenv(EnvSocket)
	if socketPath == "" {
		socketPath = filepath.Join(runtimeDir, "daemon.sock")
	}

	return Paths{
		HomeDir:     home,
		RuntimeDir:  runtimeDir,
		SocketPath:  socketPath,
		PidFilePath: filepath.Join(runtimeDir, "daemon.pid"),
		StatePath:   filepath.Join(home, "vault.json.enc"),
		AuditPath:   filepath.Join(home, "audit.jsonl"),
	}, nil
}
