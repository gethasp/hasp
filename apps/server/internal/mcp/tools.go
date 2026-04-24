package mcp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var (
	newVaultStoreFn           = store.New
	defaultKeyringFn          = store.NewDefaultKeyring
	newMCPAuditLogFn          = audit.New
	ensureSessionFn           = brokerops.EnsureSessionWithManager
	resolveBindingViewMCPFn   = (*store.Handle).ResolveBindingView
	grantProjectLeaseMCPFn    = (*store.Handle).GrantProjectLease
	getItemMCPFn              = (*store.Handle).GetItem
	captureMCPFn              = (*store.Handle).Capture
	canonicalProjectRootMCPFn = store.CanonicalProjectRoot
	authorizeReferenceMCPFn   = brokerops.AuthorizeReference
	runnerExecuteMCPFn        = runner.Execute
	loadCLIConfigMCPFn        = paths.LoadConfig
)

const (
	mcpEnvSessionToken     = "HASP_SESSION_TOKEN"
	mcpEnvAgentProjectRoot = "HASP_AGENT_PROJECT_ROOT"
	mcpEnvAgentConsumer    = "HASP_AGENT_CONSUMER"
)

func callTool(ctx context.Context, call toolCall) (map[string]any, error) {
	handle, err := openHandle(ctx)
	if err != nil {
		return nil, err
	}
	switch call.Name {
	case "hasp_list":
		return callList(ctx, handle, call)
	case "hasp_check":
		return callCheck(ctx, handle, call)
	case "hasp_run", "hasp_inject":
		return callExecute(ctx, handle, call)
	case "hasp_capture":
		return callCapture(ctx, handle, call)
	case "hasp_secret_add":
		return callSecretAdd(ctx, handle, call)
	case "hasp_secret_update":
		return callSecretUpdate(ctx, handle, call)
	case "hasp_secret_delete":
		return callSecretDelete(ctx, handle, call)
	case "hasp_secret_get":
		return callSecretGet(ctx, handle, call)
	case "hasp_secret_expose":
		return callSecretExpose(ctx, handle, call)
	case "hasp_secret_hide":
		return callSecretHide(ctx, handle, call)
	case "hasp_redact":
		text := stringArg(call.Arguments, "text", "")
		result := redactor.Apply([]byte(text), handle.ListItems())
		return map[string]any{"text": string(result.Output), "redacted": result.Redacted, "suppressed": result.Suppressed}, nil
	default:
		return nil, fmtUnsupportedTool(call.Name)
	}
}

func callList(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	projectRoot := stringArg(call.Arguments, "project_root", defaultMCPProjectRoot())
	grantProject := stringArg(call.Arguments, "grant_project", "")
	session, err := ensureSessionFn(ctx, projectRoot, defaultMCPSessionToken(call), defaultMCPHostLabel(call))
	if err != nil {
		return nil, err
	}
	binding, visible, err := ensureProjectBindingMCP(ctx, handle, projectRoot)
	if err != nil {
		return nil, err
	}
	if err := requireProjectBindingMCP(binding, projectRoot); err != nil {
		return nil, err
	}
	if grantProject != "" {
		if _, err := grantProjectLeaseMCPFn(handle, binding.ID, session.Token, parseScope(grantProject), 15*time.Minute); err != nil {
			return nil, err
		}
	}
	decision := handle.Authorize(store.AccessRequest{
		Operation:    store.OperationList,
		BindingID:    binding.ID,
		SessionToken: session.Token,
	})
	if !decision.Allowed {
		return nil, approvalRequired(decision.Reason)
	}
	return map[string]any{"visible": visible, "lease_active": true}, nil
}

func callCheck(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	projectRoot := stringArg(call.Arguments, "project_root", defaultMCPProjectRoot())
	if _, _, err := ensureProjectBindingMCP(ctx, handle, projectRoot); err != nil {
		return nil, err
	}
	root, err := canonicalProjectRootMCPFn(ctx, projectRoot)
	if err != nil {
		return nil, err
	}
	items := handle.ListItems()
	matches := make([]map[string]string, 0)
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, item := range items {
			if len(item.Value) > 0 && strings.Contains(string(data), string(item.Value)) {
				matches = append(matches, map[string]string{"path": path, "item_name": item.Name})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"matches": matches}, nil
}

func callExecute(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	projectRoot := stringArg(call.Arguments, "project_root", defaultMCPProjectRoot())
	session, err := ensureSessionFn(ctx, projectRoot, defaultMCPSessionToken(call), defaultMCPHostLabel(call))
	if err != nil {
		return nil, err
	}
	command := stringSliceArg(call.Arguments["command"])
	if len(command) == 0 {
		return nil, errors.New("command is required")
	}
	projectGrant := parseScope(stringArg(call.Arguments, "grant_project", ""))
	secretGrant := parseScope(stringArg(call.Arguments, "grant_secret", ""))
	envRefs := stringMapArg(call.Arguments["env"])
	fileRefs := stringMapArg(call.Arguments["files"])
	if call.Name == "hasp_inject" && len(fileRefs) == 0 {
		return nil, errors.New("files are required for hasp_inject")
	}
	binding, _, err := ensureProjectBindingMCP(ctx, handle, projectRoot)
	if err != nil {
		return nil, err
	}
	if err := requireProjectBindingMCP(binding, projectRoot); err != nil {
		return nil, err
	}
	items := make([]store.Item, 0, len(envRefs)+len(fileRefs))
	env := map[string]string{}
	files := map[string][]byte{}
	for envName, reference := range envRefs {
		item, err := authorizeReferenceMCPFn(ctx, handle, binding.ID, projectRoot, session.Token, reference, store.OperationRun, projectGrant, secretGrant, "", 15*time.Minute, "")
		if err != nil {
			return nil, err
		}
		env[envName] = string(item.Value)
		items = append(items, item)
	}
	for envName, reference := range fileRefs {
		item, err := authorizeReferenceMCPFn(ctx, handle, binding.ID, projectRoot, session.Token, reference, store.OperationInject, projectGrant, secretGrant, "", 15*time.Minute, "")
		if err != nil {
			return nil, err
		}
		files[envName] = item.Value
		items = append(items, item)
	}
	runResult, err := runnerExecuteMCPFn(ctx, runner.Input{ProjectRoot: projectRoot, Command: command, Env: env, Files: files})
	if err != nil {
		return nil, err
	}
	stdout := redactor.Apply(runResult.Stdout, items)
	stderr := redactor.Apply(runResult.Stderr, items)
	return map[string]any{
		"exit_code":  runResult.ExitCode,
		"stdout":     string(stdout.Output),
		"stderr":     string(stderr.Output),
		"redacted":   stdout.Redacted || stderr.Redacted,
		"suppressed": stdout.Suppressed || stderr.Suppressed,
	}, nil
}

func callCapture(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	projectRoot := stringArg(call.Arguments, "project_root", defaultMCPProjectRoot())
	session, err := ensureSessionFn(ctx, projectRoot, defaultMCPSessionToken(call), defaultMCPHostLabel(call))
	if err != nil {
		return nil, err
	}
	name := stringArg(call.Arguments, "name", "")
	kind := store.ItemKind(stringArg(call.Arguments, "kind", string(store.ItemKindKV)))
	value := stringArg(call.Arguments, "value", "")
	bind := boolArg(call.Arguments, "bind", false)
	projectGrant := parseScope(stringArg(call.Arguments, "grant_project", ""))
	secretGrant := parseScope(stringArg(call.Arguments, "grant_secret", ""))
	grantWrite := boolArg(call.Arguments, "grant_write", false)
	if name == "" {
		return nil, errors.New("name is required")
	}
	_, existingErr := getItemMCPFn(handle, name)
	creatingNew := errors.Is(existingErr, store.ErrItemNotFound)
	if existingErr != nil && !creatingNew {
		return nil, existingErr
	}
	binding, _, err := ensureProjectBindingMCP(ctx, handle, projectRoot)
	if err != nil {
		return nil, err
	}
	if err := requireProjectBindingMCP(binding, projectRoot); err != nil {
		return nil, err
	}
	if err := brokerops.AuthorizeCapture(ctx, handle, binding.ID, session.Token, name, projectGrant, secretGrant, 15*time.Minute, grantWrite); err != nil {
		return nil, err
	}
	if creatingNew && grantWrite {
		appendAuditApproval(binding.ID, name)
	}
	result, err := captureMCPFn(handle, ctx, projectRoot, name, kind, []byte(value), bind)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"reference":       result.Reference,
		"alias":           result.Alias,
		"item_name":       result.ItemName,
		"item_kind":       result.ItemKind,
		"named_reference": store.NamedReference(result.ItemName),
	}, nil
}

func openHandle(ctx context.Context) (*store.Handle, error) {
	password := os.Getenv("HASP_MASTER_PASSWORD")
	vaultStore, err := newVaultStoreFn(defaultKeyringFn())
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(password) != "" {
		return vaultStore.OpenWithPassword(ctx, password)
	}
	return vaultStore.OpenWithConvenienceUnlock(ctx)
}

func defaultMCPProjectRoot() string {
	if value := strings.TrimSpace(os.Getenv(mcpEnvAgentProjectRoot)); value != "" {
		return value
	}
	return "."
}

func defaultOptionalMCPProjectRoot() string {
	return strings.TrimSpace(os.Getenv(mcpEnvAgentProjectRoot))
}

func defaultMCPSessionToken(call toolCall) string {
	return stringArg(call.Arguments, "session_token", strings.TrimSpace(os.Getenv(mcpEnvSessionToken)))
}

func defaultMCPHostLabel(call toolCall) string {
	defaultLabel := "mcp-stdio"
	if consumer := strings.TrimSpace(os.Getenv(mcpEnvAgentConsumer)); consumer != "" {
		defaultLabel = "agent:" + consumer
	}
	return stringArg(call.Arguments, "host_label", defaultLabel)
}

func appendAuditApproval(bindingID string, itemName string) {
	log, err := newMCPAuditLogFn()
	if err != nil {
		return
	}
	_, _ = log.Append(audit.EventApprove, "agent", map[string]any{"action": "capture.write_grant", "binding_id": bindingID, "item_name": itemName})
}

func ensureProjectBindingMCP(ctx context.Context, handle *store.Handle, projectRoot string) (store.Binding, []store.VisibleReference, error) {
	binding, visible, err := resolveBindingViewMCPFn(handle, ctx, projectRoot)
	if err != nil {
		return store.Binding{}, nil, err
	}
	if binding.ID != "" {
		return binding, visible, nil
	}
	defaults, err := loadProjectDefaultsMCP()
	if err != nil {
		return store.Binding{}, nil, err
	}
	if !defaults.AutoProtectRepos {
		return binding, visible, nil
	}
	root, err := canonicalProjectRootMCPFn(ctx, projectRoot)
	if err != nil {
		return store.Binding{}, nil, err
	}
	if !pathLooksLikeGitRepoMCP(root) {
		return binding, visible, nil
	}
	installHooks := defaults.AutoInstallHooks && pathLooksLikeGitRepoMCP(root)
	if _, err := handle.UpsertBinding(ctx, root, cloneAliasSetMCP(binding.Aliases), defaults.DefaultPolicy, installHooks); err != nil {
		return store.Binding{}, nil, err
	}
	return resolveBindingViewMCPFn(handle, ctx, root)
}

func requireProjectBindingMCP(binding store.Binding, projectRoot string) error {
	if binding.ID != "" {
		return nil
	}
	return fmt.Errorf("project %q is not managed yet; run inside a git repo with auto-protect enabled or bind it explicitly", projectRoot)
}

type projectDefaultsMCP struct {
	AutoProtectRepos bool
	AutoInstallHooks bool
	DefaultPolicy    store.SecretPolicy
}

func loadProjectDefaultsMCP() (projectDefaultsMCP, error) {
	cfg, err := loadCLIConfigMCPFn()
	if err != nil {
		return projectDefaultsMCP{}, err
	}
	autoProtect := true
	if cfg.AutoProtectRepos != nil {
		autoProtect = *cfg.AutoProtectRepos
	}
	autoInstallHooks := true
	if cfg.AutoInstallHooks != nil {
		autoInstallHooks = *cfg.AutoInstallHooks
	}
	policy := store.PolicySession
	switch store.SecretPolicy(strings.TrimSpace(cfg.DefaultCapturePolicy)) {
	case store.PolicyAuto, store.PolicySession, store.PolicyAccess:
		policy = store.SecretPolicy(strings.TrimSpace(cfg.DefaultCapturePolicy))
	case "":
		policy = store.PolicySession
	}
	return projectDefaultsMCP{
		AutoProtectRepos: autoProtect,
		AutoInstallHooks: autoInstallHooks,
		DefaultPolicy:    policy,
	}, nil
}

func pathLooksLikeGitRepoMCP(root string) bool {
	root = strings.TrimSpace(root)
	if root == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(root, ".git"))
	if err != nil {
		return false
	}
	return info.IsDir() || info.Mode().IsRegular()
}

func cloneAliasSetMCP(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func stringArg(values map[string]any, key string, fallback string) string {
	value, ok := values[key]
	if !ok {
		return fallback
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fallback
}

func boolArg(values map[string]any, key string, fallback bool) bool {
	value, ok := values[key]
	if !ok {
		return fallback
	}
	if b, ok := value.(bool); ok {
		return b
	}
	return fallback
}

func stringMapArg(value any) map[string]string {
	result := map[string]string{}
	source, ok := value.(map[string]any)
	if !ok {
		return result
	}
	for key, item := range source {
		if text, ok := item.(string); ok {
			result[key] = text
		}
	}
	return result
}

func stringSliceArg(value any) []string {
	source, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(source))
	for _, item := range source {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func parseScope(value string) store.GrantScope {
	switch value {
	case string(store.GrantOnce):
		return store.GrantOnce
	case string(store.GrantSession):
		return store.GrantSession
	case string(store.GrantWindow):
		return store.GrantWindow
	default:
		return store.GrantOnce
	}
}

func approvalRequired(reason string) error {
	return fmt.Errorf("approval required: %s", reason)
}

func fmtUnsupportedTool(name string) error {
	return fmt.Errorf("unsupported tool %q", name)
}
