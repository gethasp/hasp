package runtime

import (
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

// secretEnvFDVar names the environment variable that tells a freshly-spawned
// daemon which inherited file descriptor carries its sensitive environment
// (master password, backup passphrase). The fd value itself is not sensitive.
const secretEnvFDVar = "HASP_SECRET_ENV_FD"

// sensitiveDaemonEnvNames are the env vars that hold vault-unlocking secrets. The
// daemon reads them for non-interactive (headless) unlock/backup, but they must
// NOT be inherited into the long-lived daemon's environment, where they would
// sit in /proc/<pid>/environ readable by same-UID processes (hasp-f373). They are
// stripped from the spawned daemon's env and passed over a one-shot pipe instead.
var sensitiveDaemonEnvNames = []string{
	"HASP_MASTER_PASSWORD",
	"HASP_BACKUP_PASSPHRASE",
}

var (
	daemonSecretEnvMu sync.RWMutex
	daemonSecretEnv   map[string]string
)

// daemonSecretGetenv returns a sensitive value provided over the one-shot fd when
// present (daemon path), otherwise falls back to os.Getenv (CLI / non-daemon
// path, where reading the process env is fine for a short-lived command).
func daemonSecretGetenv(key string) string {
	daemonSecretEnvMu.RLock()
	v, ok := daemonSecretEnv[key]
	daemonSecretEnvMu.RUnlock()
	if ok {
		return v
	}
	return os.Getenv(key)
}

// loadDaemonSecretEnvFromFD reads the sensitive env blob from the inherited fd
// named by HASP_SECRET_ENV_FD (if set), parses it, and stores it for
// daemonSecretGetenv. The fd is read to EOF and closed. Safe to call when the
// var is unset (no-op). Called once at daemon startup.
func loadDaemonSecretEnvFromFD() {
	raw := strings.TrimSpace(os.Getenv(secretEnvFDVar))
	if raw == "" {
		return
	}
	// Clear the marker so child processes the daemon spawns don't inherit it.
	_ = os.Unsetenv(secretEnvFDVar)
	fd, err := strconv.Atoi(raw)
	if err != nil || fd < 0 {
		return
	}
	f := os.NewFile(uintptr(fd), "hasp-secret-env")
	if f == nil {
		return
	}
	defer f.Close()
	blob, err := io.ReadAll(io.LimitReader(f, 1<<16))
	if err != nil {
		return
	}
	parsed := parseSecretEnvBlob(blob)
	daemonSecretEnvMu.Lock()
	daemonSecretEnv = parsed
	daemonSecretEnvMu.Unlock()
}

// encodeSecretEnvBlob serializes the present sensitive vars from environ as a
// newline-delimited KEY=VALUE blob. Values may not contain newlines (env values
// never do in practice); a value with a newline is truncated at it defensively.
func encodeSecretEnvBlob(environ []string) []byte {
	var b strings.Builder
	for _, name := range sensitiveDaemonEnvNames {
		prefix := name + "="
		for _, kv := range environ {
			if !strings.HasPrefix(kv, prefix) {
				continue
			}
			value := kv[len(prefix):]
			if i := strings.IndexByte(value, '\n'); i >= 0 {
				value = value[:i]
			}
			b.WriteString(name)
			b.WriteByte('=')
			b.WriteString(value)
			b.WriteByte('\n')
			break
		}
	}
	return []byte(b.String())
}

func parseSecretEnvBlob(blob []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(blob), "\n") {
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[name] = value
	}
	return out
}

// hasSensitiveEnv reports whether any sensitive var is present in environ.
func hasSensitiveEnv(environ []string) bool {
	for _, name := range sensitiveDaemonEnvNames {
		prefix := name + "="
		for _, kv := range environ {
			if strings.HasPrefix(kv, prefix) {
				return true
			}
		}
	}
	return false
}
