package hooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const revisionMarker = "# HASP-HOOK-REVISION: 2"

type HookStatus struct {
	Path       string `json:"path"`
	State      string `json:"state"`
	Present    bool   `json:"present"`
	Managed    bool   `json:"managed"`
	Executable bool   `json:"executable"`
	Current    bool   `json:"current"`
	Detail     string `json:"detail,omitempty"`
}

type Diagnostics struct {
	State     string     `json:"state"`
	HooksDir  string     `json:"hooks_dir,omitempty"`
	Installed bool       `json:"installed"`
	Ready     bool       `json:"ready"`
	ScanState string     `json:"scan_state"`
	PreCommit HookStatus `json:"pre_commit"`
	PrePush   HookStatus `json:"pre_push"`
	Repair    string     `json:"repair,omitempty"`
}

// Inspect reads configuration and hook files without running hooks or scanning
// repository content. A ready installation still needs a working vault at run
// time; a custom hook's behavior is deliberately left unverified.
func Inspect(projectRoot string) Diagnostics {
	result := Diagnostics{ScanState: "not_run"}
	plan, err := ResolveInstallPlan(projectRoot)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotGitRepo):
			result.State = "not_git"
		case errors.Is(err, ErrHooksDisabled):
			result.State = "disabled"
		case errors.Is(err, ErrUnsafeHooksDir):
			result.State = "unsafe_path"
		default:
			result.State = "unavailable"
		}
		result.PreCommit.State, result.PrePush.State = result.State, result.State
		result.PreCommit.Detail, result.PrePush.Detail = err.Error(), err.Error()
		if result.State != "not_git" {
			result.Repair = "review Git's core.hooksPath and directory access; HASP did not change the configuration"
		}
		return result
	}
	result.HooksDir = plan.HooksDir
	result.PreCommit = inspectHook(filepath.Join(plan.HooksDir, "pre-commit"))
	result.PrePush = inspectHook(filepath.Join(plan.HooksDir, "pre-push"))
	result.Installed = result.PreCommit.Managed && result.PreCommit.Executable && result.PrePush.Managed && result.PrePush.Executable
	result.Ready = result.Installed && result.PreCommit.Current && result.PrePush.Current
	switch {
	case result.Ready:
		result.State = "ready"
	case result.Installed:
		result.State = "outdated"
	case result.PreCommit.State == "unreadable" || result.PrePush.State == "unreadable":
		result.State = "unavailable"
	case result.PreCommit.Managed || result.PrePush.Managed:
		result.State = "partial"
	case !result.PreCommit.Present && !result.PrePush.Present:
		result.State = "missing"
	default:
		result.State = "custom_unverified"
	}
	if !result.Ready {
		result.Repair = "hasp project hooks --project-root " + shellSingleQuote(plan.ProjectRoot) + " --install"
	}
	return result
}

func inspectHook(path string) HookStatus {
	result := HookStatus{Path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		result.State = "missing"
		return result
	}
	if err != nil {
		result.State, result.Detail = "unreadable", err.Error()
		return result
	}
	result.Present = true
	if !info.Mode().IsRegular() {
		result.State = "custom_unverified"
		result.Detail = "hook is not a regular file; its target and behavior were not checked"
		return result
	}
	result.Executable = hookExecutable(path, info)
	data, err := os.ReadFile(path)
	if err != nil {
		result.State, result.Detail = "unreadable", err.Error()
		return result
	}
	result.Managed = strings.Contains(string(data), marker)
	result.Current = result.Managed && strings.Contains("\n"+string(data)+"\n", "\n"+revisionMarker+"\n")
	switch {
	case !result.Managed:
		result.State = "custom_unverified"
		result.Detail = "custom hook was not executed or verified"
	case !result.Executable:
		result.State = "not_executable"
		result.Detail = "Git will not run this hook for the current user"
	case !result.Current:
		result.State = "outdated"
		result.Detail = "reinstall to check the final index and outgoing objects"
	default:
		result.State = "ready"
	}
	return result
}
