package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Delivery checks are human-only metadata. They never execute consumers,
// request grants, or probe Keychain access.
type doctorDeliveryCheck struct {
	Name, State, Detail string
}

func doctorConsumerChecks(root string, handle *store.Handle) []doctorDeliveryCheck {
	checks := []doctorDeliveryCheck{{"keychain_convenience", "not_probed", "vault access succeeded; Keychain consent is not tested by doctor; use convenience-disabled setup over SSH"}}
	for _, app := range handle.ListAppConsumers() {
		check := doctorDeliveryCheck{"app_delivery", "ready", fmt.Sprintf("%q: configured command and refs are available; runtime grants still apply", app.Name)}
		appRoot := app.ProjectRoot
		if appRoot == "" {
			appRoot = root
		}
		switch {
		case validateAppMappings(app) != nil:
			check.State, check.Detail = "invalid_mapping", fmt.Sprintf("%q: reconnect the app with valid delivery mappings", app.Name)
		case len(app.Command) == 0 || !projectTargetCommandAvailable(appRoot, store.ManifestTarget{Command: app.Command}):
			check.State, check.Detail = "command_missing", fmt.Sprintf("%q: command executable is unavailable on this PATH", app.Name)
		default:
			for _, binding := range app.Bindings {
				if _, err := handle.GetItem(binding.SecretName); err != nil {
					check.State, check.Detail = "ref_missing", fmt.Sprintf("%q: a configured vault ref is missing", app.Name)
					break
				}
			}
		}
		checks = append(checks, check)
		if app.LauncherPath != "" {
			state := "ready"
			info, err := os.Lstat(app.LauncherPath)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				state = "missing_or_unsafe"
			} else if !doctorPathContains(filepath.Dir(app.LauncherPath)) {
				state = "not_on_path"
			}
			checks = append(checks, doctorDeliveryCheck{"app_launcher", state, fmt.Sprintf("%q: use hasp app install to repair; add the launcher directory to PATH", app.Name)})
		}
	}
	for _, agent := range handle.ListAgentConsumers() {
		state := "present"
		if info, err := os.Stat(agent.ConfigPath); err != nil || !info.Mode().IsRegular() {
			state = "missing"
		}
		checks = append(checks, doctorDeliveryCheck{"agent_config", state, fmt.Sprintf("%q: config file presence only; use agent connect to repair and verify the client loads its HASP integration", agent.Name)})
	}
	if manifest, err := store.LoadRepoManifest(root); err == nil {
		for _, target := range manifest.Targets {
			expansion, err := store.ExpandManifestTarget(root, target.Name)
			if err != nil {
				continue
			}
			drift, err := handle.ManifestTargetDrift(root, expansion)
			state := "reviewed"
			if err != nil || !drift.Known || drift.Changed {
				state = "review_required"
			}
			checks = append(checks, doctorDeliveryCheck{"target_review", state, fmt.Sprintf("%q: use hasp project target review after inspecting the target", target.Name)})
		}
	}
	return checks
}

func doctorPathContains(dir string) bool {
	for _, entry := range filepath.SplitList(os.Getenv("PATH")) {
		if entry != "" && cleanComparablePath(entry) == cleanComparablePath(dir) {
			return true
		}
	}
	return false
}

func doctorTempDirectory(runtimeDir, root string) doctorDeliveryCheck {
	check := doctorDeliveryCheck{"delivery_temp_dir", "ready", "runtime delivery directory is outside the project and private; no files created by this check"}
	canonicalRoot := doctorComparableDirectory(root)
	for _, dir := range []string{runtimeDir, filepath.Join(runtimeDir, "inject")} {
		canonical := doctorComparableDirectory(dir)
		if canonicalRoot != "" && (canonical == canonicalRoot || strings.HasPrefix(canonical, canonicalRoot+string(filepath.Separator))) {
			check.State, check.Detail = "inside_project", "move HASP runtime state outside the repository before file delivery"
			return check
		}
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			check.State, check.Detail = "not_created", "runtime delivery directory will be created privately on first use"
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			check.State, check.Detail = "unsafe", "runtime delivery directory must be a private directory without symlinks"
			return check
		}
	}
	return check
}

func doctorComparableDirectory(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	parent, suffix := abs, ""
	for {
		if resolved, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Join(resolved, suffix)
		}
		next := filepath.Dir(parent)
		if next == parent {
			return abs
		}
		suffix = filepath.Join(filepath.Base(parent), suffix)
		parent = next
	}
}
