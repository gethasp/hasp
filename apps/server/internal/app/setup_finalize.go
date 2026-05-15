package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

const setupBrokeredProofEnv = "HASP_SETUP_PROOF"

func setupImportInput(prompt *setupPrompter, opts setupOptions) io.Reader {
	if opts.ImportPath == "-" {
		return prompt.reader
	}
	return nil
}

func setupImportAndBind(ctx context.Context, handle *store.Handle, projectRoot string, opts setupOptions, prompt *setupPrompter) ([]store.ImportedItem, error) {
	imported := []store.ImportedItem{}
	if opts.ImportPath != "" {
		prepared, err := prepareImport(opts.ImportPath, opts.ImportFormat, "", setupImportInput(prompt, opts), opts.BindImports, nil)
		if err != nil {
			return nil, err
		}
		defer prepared.Cleanup()
		result, err := setupImportPathFn(ctx, handle, prepared.Path, store.ImportOptions{
			ProjectRoot:   projectRoot,
			BindToProject: opts.BindImports,
		})
		if err != nil {
			return nil, err
		}
		imported = append(imported, result.Imported...)
	}
	for alias, item := range opts.Aliases {
		if _, err := handle.GetItem(item); err != nil {
			return nil, err
		}
		opts.Aliases[alias] = item
	}
	for _, itemName := range opts.BindItems {
		alias, err := handle.BindItemAlias(ctx, projectRoot, itemName)
		if err != nil {
			return nil, err
		}
		imported = append(imported, store.ImportedItem{Name: itemName, Alias: alias})
	}
	return imported, nil
}

func setupFinalizeBinding(ctx context.Context, handle *store.Handle, projectRoot string, opts setupOptions) (store.Binding, []store.VisibleReference, error) {
	aliases := cloneAliasSet(opts.Aliases)
	current, visible, err := setupResolveBindingViewFn(ctx, handle, projectRoot)
	if err == nil {
		for alias, item := range current.Aliases {
			aliases[alias] = item
		}
		_ = visible
	}
	if _, err := bindProject(ctx, handle, projectRoot, aliases, opts.DefaultPolicy, opts.InstallHooks.value); err != nil {
		return store.Binding{}, nil, err
	}
	binding, visible, err := setupResolveBindingViewFn(ctx, handle, projectRoot)
	return binding, visible, err
}

func setupAtomicWrite(path string, existing []byte, updated []byte) (string, bool, error) {
	if bytes.Equal(existing, updated) {
		return "", false, nil
	}
	if err := setupMkdirAllFn(filepath.Dir(path), 0o700); err != nil {
		return "", false, err
	}
	backupPath := ""
	if len(existing) > 0 {
		backupPath = fmt.Sprintf("%s.bak.%s", path, setupNowFn().Format("20060102-150405"))
		if err := setupWriteFileFn(backupPath, existing, 0o600); err != nil {
			return "", false, err
		}
	}
	tempFile, err := setupCreateTempFn(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return backupPath, false, err
	}
	tempName := tempFile.Name()
	defer os.Remove(tempName)
	if _, err := setupTempWriteFn(tempFile, updated); err != nil {
		_ = setupTempCloseFn(tempFile)
		return backupPath, false, err
	}
	if err := setupTempChmodFn(tempFile, 0o600); err != nil {
		_ = setupTempCloseFn(tempFile)
		return backupPath, false, err
	}
	if err := setupTempCloseFn(tempFile); err != nil {
		return backupPath, false, err
	}
	if err := setupRenameFn(tempName, path); err != nil {
		return backupPath, false, err
	}
	return backupPath, true, nil
}

func setupVerifyHarness(ctx context.Context, agents []setupAgentSpec) (map[string]any, error) {
	request := bytes.NewBufferString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n")
	var output bytes.Buffer
	if err := setupMCPServeFn(ctx, request, &output); err != nil {
		return nil, err
	}
	if !strings.Contains(output.String(), "hasp_list") {
		return nil, errors.New("setup verification failed: hasp_list missing from MCP tools/list")
	}
	agentIDs := make([]string, 0, len(agents))
	for _, agent := range agents {
		agentIDs = append(agentIDs, agent.ID)
	}
	return map[string]any{
		"mcp": map[string]any{
			"ready": true,
			"tools": setupMCPToolNamesFn(),
		},
		"agents": agentIDs,
	}, nil
}

func setupRescueMap(available bool, reason string, commands []string, nextCommand string) map[string]any {
	return map[string]any{
		"available":    available,
		"reason":       reason,
		"commands":     commands,
		"next_command": nextCommand,
		"performed":    false,
	}
}

func setupVerifyBrokeredProof(ctx context.Context, projectRoot string, visible []store.VisibleReference) (map[string]any, error) {
	result := map[string]any{
		"performed": false,
		"ready":     false,
	}
	if strings.TrimSpace(projectRoot) == "" {
		result["reason"] = "no project root"
		result["state"] = "unavailable"
		result["rescue"] = setupRescueMap(false, "", []string{}, "")
		return result, nil
	}
	reference := setupFirstExecutableProofReference(visible)
	if reference == "" {
		const rescueReason = "no brokered reference available yet"
		rescueCmds := []string{
			`hasp secret add --bind --project-root "` + projectRoot + `"`,
			`hasp import <path> --bind --project-root "` + projectRoot + `"`,
		}
		result["reason"] = rescueReason
		result["state"] = "unavailable"
		result["rescue"] = setupRescueMap(true, rescueReason, rescueCmds, setupBrokeredProofCommand(projectRoot, "@SECRET_NAME"))
		return result, nil
	}
	result["reference"] = reference
	result["command"] = setupBrokeredProofCommand(projectRoot, reference)
	result["ready"] = true
	result["state"] = "ready"
	result["rescue"] = setupRescueMap(false, "", []string{}, setupBrokeredProofCommand(projectRoot, reference))
	return result, nil
}

func setupNotes(agents []setupAgentSpec, configExisted bool, opts setupOptions, convenienceState string, convenienceDetail string) []string {
	notes := []string{
		"setup writes only local MCP config stanzas for selected agents",
		"setup never writes secret values into agent config, repo files, or shell profiles",
		"convenience materialization remains an explicit separate path via hasp write-env",
	}
	if configExisted {
		notes = append(notes, "existing agent config files were backed up before mutation")
	}
	if opts.BindImports {
		notes = append(notes, "imported items were bound only because bind-imports was explicitly requested")
	}
	if convenienceState == "unavailable" {
		notes = append(notes, "convenience unlock was requested but the macOS login keychain was unavailable")
		if strings.TrimSpace(convenienceDetail) != "" {
			notes = append(notes, "convenience unlock detail: "+setupConvenienceDetailForDisplay(convenienceDetail))
		}
	}
	for _, agent := range agents {
		notes = append(notes, "configured agent target: "+agent.ID)
	}
	return notes
}

func setupNextSteps(projectRoot string, binding store.Binding, haspHome string, convenienceState string, convenienceDetail string, autoProtect bool, autoInstallHooks bool) []string {
	steps := []string{
		"verify MCP with: printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\\n' | hasp mcp",
	}
	if strings.TrimSpace(projectRoot) != "" {
		steps = append(steps, "review the repo binding with: hasp project status --project-root \""+projectRoot+"\"")
	}
	if strings.TrimSpace(projectRoot) != "" && len(binding.Aliases) > 0 {
		proofRef := setupFirstProofReferenceFromAliases(binding.Aliases)
		steps = append(steps, "run a brokered proof command: "+setupBrokeredProofCommand(projectRoot, proofRef))
	} else {
		steps = append(steps, "the first time you use HASP in a project, it will adopt that project automatically")
		steps = append(steps, "inspect an adopted repo with: hasp project status --project-root /path/to/repo")
	}
	if convenienceState != "enabled" {
		steps = append(steps, "future CLI commands still need HASP_MASTER_PASSWORD because convenience unlock is not active")
		if strings.TrimSpace(convenienceDetail) != "" {
			steps = append(steps, "this is a macOS login keychain issue, not a HASP master-password rejection")
			steps = append(steps, "repair convenience unlock with: security unlock-keychain ~/Library/Keychains/login.keychain-db && hasp setup --enable-convenience-unlock=always")
		}
	}
	steps = append(steps, "saved CLI config keeps HASP_HOME at "+haspHome)
	return steps
}

func setupSavedHomeLooksUsable(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false
	} else if err != nil {
		return false
	}
	tempRoot := strings.TrimSpace(setupTempDirFn())
	if tempRoot == "" {
		return true
	}
	absPath, err := setupAbsFn(path)
	if err != nil {
		return false
	}
	absTemp, err := setupAbsFn(tempRoot)
	if err != nil {
		return false
	}
	if absPath == absTemp || strings.HasPrefix(absPath, absTemp+string(filepath.Separator)) {
		return false
	}
	return true
}

func defaultSetupConvenienceUnlock() bool {
	return setupGOOS == "darwin"
}

func setupBoolPointer(value bool) *bool {
	v := value
	return &v
}

func setupSetEnv(name string, value string) (func(), error) {
	previous, had := os.LookupEnv(name)
	if err := os.Setenv(name, value); err != nil {
		return nil, err
	}
	return func() {
		if had {
			_ = os.Setenv(name, previous)
			return
		}
		_ = os.Unsetenv(name)
	}, nil
}

func expandHome(value string) (string, error) {
	if value == "~" || strings.HasPrefix(value, "~/") {
		home, err := setupUserHomeDirFn()
		if err != nil {
			return "", err
		}
		if value == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(value, "~/")), nil
	}
	return value, nil
}

func withinPath(path string, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func strconvQuote(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func setupFirstProofReference(visible []store.VisibleReference) string {
	if len(visible) == 0 {
		return ""
	}
	candidate := visible[0]
	if strings.TrimSpace(candidate.NamedReference) != "" {
		return candidate.NamedReference
	}
	return candidate.Alias
}

// setupFirstExecutableProofReference returns a reference form that the runtime
// can resolve end-to-end.  Aliases (e.g. "secret_01") round-trip through
// resolveRef; named references (e.g. "@API_TOKEN") are display-oriented and
// may not bind at runtime, so we prefer the alias when present.
func setupFirstExecutableProofReference(visible []store.VisibleReference) string {
	if len(visible) == 0 {
		return ""
	}
	candidate := visible[0]
	if strings.TrimSpace(candidate.Alias) != "" {
		return candidate.Alias
	}
	return candidate.NamedReference
}

func setupFirstProofReferenceFromAliases(aliases map[string]string) string {
	if len(aliases) == 0 {
		return ""
	}
	keys := make([]string, 0, len(aliases))
	for alias := range aliases {
		keys = append(keys, alias)
	}
	sort.Strings(keys)
	return keys[0]
}

func setupBrokeredProofCommand(projectRoot string, reference string) string {
	return fmt.Sprintf(
		`hasp run --project-root "%s" --env %s=%s --grant-project window --grant-secret session --grant-window 15m -- sh -c 'test -n "$%s"'`,
		projectRoot,
		setupBrokeredProofEnv,
		reference,
		setupBrokeredProofEnv,
	)
}
