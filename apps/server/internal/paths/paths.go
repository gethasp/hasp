package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	EnvHome   = "HASP_HOME"
	EnvSocket = "HASP_SOCKET"

	// EnvTest is the name of the environment variable that signals a
	// non-go-test context that still wants test-mode path isolation (e.g. a
	// subprocess spawned by a test helper).  Set it to "1".
	EnvTest = "HASP_TEST"
)

var userConfigDir = os.UserConfigDir
var userHomeDir = os.UserHomeDir
var pathStat = os.Stat

// resolveGuardDisabled is a package-level seam used only by tests inside the
// paths package itself that need to exercise the legacy-home or config-dir
// fallback code paths while having already stubbed userHomeDir/userConfigDir
// to safe temp directories.  External packages must NOT set this; they must
// set HASP_HOME instead.
var resolveGuardDisabled bool

type Paths struct {
	HomeDir     string
	RuntimeDir  string
	SocketPath  string
	PidFilePath string
	StatePath   string
	AuditPath   string
}

// Resolve computes the set of well-known paths used by the hasp server and
// CLI tools.
//
// # Test-isolation guard
//
// When running inside a Go test binary (testing.Testing() == true) or when
// the HASP_TEST=1 environment variable is set, Resolve refuses to fall back
// to the real user home directory.  If HASP_HOME is not set explicitly in
// one of those contexts, Resolve returns an error whose message contains
// "HASP_HOME" and "set explicitly".
//
// This prevents tests from accidentally writing to ~/.hasp/audit.jsonl (or
// any other production path).  Fix: call t.Setenv("HASP_HOME", t.TempDir())
// at the start of every test, or set HASP_HOME in TestMain.
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
		// Hard guard: refuse to touch the real user home in test contexts.
		// resolveGuardDisabled may only be set by intra-package tests that have
		// already replaced userHomeDir/userConfigDir with safe temp-dir stubs.
		if !resolveGuardDisabled && (testing.Testing() || os.Getenv(EnvTest) == "1") {
			return Paths{}, fmt.Errorf(
				"HASP_HOME must be set explicitly in test contexts; " +
					"call t.Setenv(\"HASP_HOME\", t.TempDir()) or set it in TestMain",
			)
		}

		legacyHome, err := existingLegacyHome()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve legacy home: %w", err)
		}
		if legacyHome != "" {
			home = legacyHome
		}
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

func existingLegacyHome() (string, error) {
	home, err := userHomeDir()
	if err != nil {
		return "", err
	}
	legacyHome := filepath.Join(home, ".hasp")
	if _, err := pathStat(filepath.Join(legacyHome, "vault.json.enc")); err == nil {
		return legacyHome, nil
	} else if os.IsNotExist(err) {
		return "", nil
	} else {
		return "", err
	}
}
