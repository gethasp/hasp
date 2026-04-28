package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
)

const (
	haspPathBlockStart = "# >>> hasp path >>>"
	haspPathBlockEnd   = "# <<< hasp path <<<"
)

type appPathUpdateResult struct {
	ConfigPath string `json:"config_path,omitempty"`
	Changed    bool   `json:"changed"`
}

func ensureLauncherDirOnPathChoice(ctx context.Context, explicit setupOptionalBool, stdin io.Reader, stdout io.Writer, stderr io.Writer, launcherDir string) (appPathUpdateResult, error) {
	if pathContainsDir(os.Getenv("PATH"), launcherDir) {
		return appPathUpdateResult{}, nil
	}
	shouldUpdate := explicit.set && explicit.value
	if !explicit.set {
		if globalFlagsFromContext(ctx).yes {
			// --yes selects the safer "no PATH change" default for this prompt;
			// users who want the change should pass --add-to-path=always.
		} else {
			file, ok := ttyutil.StdinFile(stdin)
			if ok && secretIsCharDeviceFn(file) {
				prompt := newSecretPrompt(stdin, stdout, stderr)
				value, err := prompt.confirm(fmt.Sprintf("Add %s to your shell PATH", launcherDir), false)
				if err != nil {
					return appPathUpdateResult{}, err
				}
				shouldUpdate = value
			}
		}
	}
	if !shouldUpdate {
		return appPathUpdateResult{}, nil
	}
	configPath, changed, err := ensureLauncherDirOnPath(launcherDir)
	if err != nil {
		return appPathUpdateResult{}, err
	}
	return appPathUpdateResult{ConfigPath: configPath, Changed: changed}, nil
}

func ensureLauncherDirOnPath(launcherDir string) (string, bool, error) {
	configPath, err := launcherShellConfigPath()
	if err != nil {
		return "", false, err
	}
	existing, err := appReadFileFn(configPath)
	if err != nil && !os.IsNotExist(err) {
		return "", false, err
	}
	updated := upsertPathBlock(string(existing), launcherDir, filepath.Base(appCurrentShellFn()))
	if string(existing) == updated {
		return configPath, false, nil
	}
	if err := appMkdirAllFn(filepath.Dir(configPath), 0o700); err != nil {
		return "", false, err
	}
	if err := appWriteFileFn(configPath, []byte(updated), 0o600); err != nil {
		return "", false, err
	}
	return configPath, true, nil
}

func launcherShellConfigPath() (string, error) {
	home, err := appUserHomeDirFn()
	if err != nil {
		return "", err
	}
	switch filepath.Base(appCurrentShellFn()) {
	case "zsh":
		return filepath.Join(home, ".zshrc"), nil
	case "bash":
		return filepath.Join(home, ".bashrc"), nil
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish"), nil
	default:
		return filepath.Join(home, ".profile"), nil
	}
}

func upsertPathBlock(existing string, launcherDir string, shell string) string {
	block := renderPathBlock(launcherDir, shell)
	start := strings.Index(existing, haspPathBlockStart)
	end := strings.Index(existing, haspPathBlockEnd)
	if start >= 0 && end >= start {
		end += len(haspPathBlockEnd)
		replaced := existing[:start] + block + existing[end:]
		return normalizeConfigText(replaced)
	}
	if strings.TrimSpace(existing) == "" {
		return block
	}
	if strings.HasSuffix(existing, "\n") {
		return normalizeConfigText(existing + "\n" + block)
	}
	return normalizeConfigText(existing + "\n\n" + block)
}

func renderPathBlock(launcherDir string, shell string) string {
	switch shell {
	case "fish":
		return haspPathBlockStart + "\nset -gx PATH " + strconvQuote(launcherDir) + " $PATH\n" + haspPathBlockEnd + "\n"
	default:
		return haspPathBlockStart + "\nexport PATH=" + strconvQuote(launcherDir) + ":$PATH\n" + haspPathBlockEnd + "\n"
	}
}

func normalizeConfigText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.TrimRight(value, "\n")
	return value + "\n"
}

func pathContainsDir(pathValue string, target string) bool {
	target = filepath.Clean(strings.TrimSpace(target))
	for _, entry := range filepath.SplitList(pathValue) {
		if filepath.Clean(strings.TrimSpace(entry)) == target {
			return true
		}
	}
	return false
}
