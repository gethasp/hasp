package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/hooks"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/projectcontext"
	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/reposcan"
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
	authorizeAndConsumeMCPFn  = (*store.Handle).AuthorizeAndConsume
	runnerExecuteMCPFn        = runner.Execute
	reposcanScanMCPFn         = reposcan.Scan
	loadCLIConfigMCPFn        = paths.LoadConfig
	installHooksMCPFn         = hooks.Install
)

const (
	mcpEnvSessionToken     = "HASP_SESSION_TOKEN"
	mcpEnvAgentProjectRoot = "HASP_AGENT_PROJECT_ROOT"
	mcpEnvAgentConsumer    = "HASP_AGENT_CONSUMER"
	mcpEnvUnsafeWriteTools = "HASP_MCP_ENABLE_UNSAFE_SECRET_WRITE_TOOLS"
	mcpToolOutputByteLimit = 64 << 10
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
	case "hasp_targets":
		return callTargets(ctx, handle, call)
	case "hasp_target_explain":
		return callTargetExplain(ctx, call)
	case "hasp_run", "hasp_inject":
		return callExecute(ctx, handle, call)
	case "hasp_capture":
		if !mcpUnsafeSecretWriteToolsEnabled() {
			return nil, unsafeSecretWriteToolDisabled(call.Name)
		}
		return callCapture(ctx, handle, call)
	case "hasp_secret_add":
		if !mcpUnsafeSecretWriteToolsEnabled() {
			return nil, unsafeSecretWriteToolDisabled(call.Name)
		}
		return callSecretAdd(ctx, handle, call)
	case "hasp_secret_update":
		if !mcpUnsafeSecretWriteToolsEnabled() {
			return nil, unsafeSecretWriteToolDisabled(call.Name)
		}
		return callSecretUpdate(ctx, handle, call)
	case "hasp_secret_delete":
		if !mcpUnsafeSecretWriteToolsEnabled() {
			return nil, unsafeSecretWriteToolDisabled(call.Name)
		}
		return callSecretDelete(ctx, handle, call)
	case "hasp_secret_get":
		return callSecretGet(ctx, handle, call)
	case "hasp_secret_expose":
		if !mcpUnsafeSecretWriteToolsEnabled() {
			return nil, unsafeSecretWriteToolDisabled(call.Name)
		}
		return callSecretExpose(ctx, handle, call)
	case "hasp_secret_hide":
		if !mcpUnsafeSecretWriteToolsEnabled() {
			return nil, unsafeSecretWriteToolDisabled(call.Name)
		}
		return callSecretHide(ctx, handle, call)
	case "hasp_redact":
		text := stringArg(call.Arguments, "text", "")
		result := redactor.Apply([]byte(text), handle.ListItems())
		return map[string]any{"text": string(result.Output), "redacted": result.Redacted, "suppressed": result.Suppressed}, nil
	default:
		return nil, fmtUnsupportedTool(call.Name)
	}
}

func mcpUnsafeSecretWriteToolsEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(mcpEnvUnsafeWriteTools))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func unsafeSecretWriteToolDisabled(name string) error {
	return fmt.Errorf("%s is disabled by default because it mutates vault or project secret state through the MCP transcript; use the hasp CLI or set %s=1 only in a trusted local harness", name, mcpEnvUnsafeWriteTools)
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
		scope, err := parseScope(grantProject, store.GrantOnce)
		if err != nil {
			return nil, err
		}
		if _, err := grantProjectLeaseMCPFn(handle, binding.ID, session.Token, scope, 15*time.Minute); err != nil {
			return nil, err
		}
	}
	decision, err := authorizeAndConsumeMCPFn(handle, store.AccessRequest{
		Operation:    store.OperationList,
		BindingID:    binding.ID,
		SessionToken: session.Token,
	})
	if err != nil {
		return nil, err
	}
	if !decision.Allowed {
		return nil, approvalRequired(decision.Reason)
	}
	return map[string]any{"visible": visible, "lease_active": true}, nil
}

func callCheck(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	projectRoot := stringArg(call.Arguments, "project_root", defaultMCPProjectRoot())
	if _, _, err := requireMCPProjectAuthorization(ctx, handle, call, projectRoot); err != nil {
		return nil, err
	}
	root, err := canonicalProjectRootMCPFn(ctx, projectRoot)
	if err != nil {
		return nil, err
	}
	result, err := reposcanScanMCPFn(ctx, root, handle.ListItems(), reposcan.DefaultMaxFileBytes, reposcan.DefaultDeps())
	if err != nil {
		return nil, err
	}
	return map[string]any{"matches": result.Matches, "skipped": result.Skipped, "walker": result.Walker}, nil
}

func callTargets(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	projectRoot := stringArg(call.Arguments, "project_root", defaultMCPProjectRoot())
	if _, _, err := requireMCPProjectAuthorization(ctx, handle, call, projectRoot); err != nil {
		return nil, err
	}
	root, err := canonicalProjectRootMCPFn(ctx, projectRoot)
	if err != nil {
		return nil, err
	}
	manifest, identity, err := store.LoadRepoManifestWithIdentity(root)
	if err != nil {
		return nil, err
	}
	targets := make([]map[string]any, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		refs := make([]string, 0, len(target.Delivery))
		kinds := make([]string, 0, len(target.Delivery))
		prereqs := make([]map[string]any, 0, len(target.Delivery))
		for _, delivery := range target.Delivery {
			refs = append(refs, delivery.Ref)
			kinds = append(kinds, delivery.As)
			_, err := handle.ResolveReference(ctx, root, delivery.Ref)
			prereqs = append(prereqs, map[string]any{
				"ref":     delivery.Ref,
				"kind":    delivery.As,
				"present": err == nil,
			})
		}
		targets = append(targets, map[string]any{
			"name":           target.Name,
			"description":    sanitizeMCPDescription(target.Description),
			"refs":           uniqueStrings(refs),
			"delivery_kinds": uniqueStrings(kinds),
			"prerequisites":  prereqs,
		})
	}
	return map[string]any{"manifest_hash": identity, "targets": targets}, nil
}

func callTargetExplain(ctx context.Context, call toolCall) (map[string]any, error) {
	projectRoot := stringArg(call.Arguments, "project_root", defaultMCPProjectRoot())
	targetName := strings.TrimSpace(stringArg(call.Arguments, "target", ""))
	if targetName == "" {
		return nil, errors.New("target is required")
	}
	root, err := canonicalProjectRootMCPFn(ctx, projectRoot)
	if err != nil {
		return nil, err
	}
	expansion, err := store.ExpandManifestTarget(root, targetName)
	if err != nil {
		return nil, err
	}
	kinds := make([]string, 0, 3)
	if len(expansion.Env) > 0 {
		kinds = append(kinds, store.ManifestDeliveryEnv)
	}
	if len(expansion.Files) > 0 {
		kinds = append(kinds, store.ManifestDeliveryFile)
	}
	if len(expansion.XCConfig) > 0 {
		kinds = append(kinds, store.ManifestDeliveryXCConfig)
	}
	return map[string]any{
		"target":                expansion.TargetName,
		"target_root":           expansion.TargetRoot,
		"manifest_hash":         expansion.ManifestHash,
		"refs":                  expansion.Refs,
		"destinations":          expansion.Destinations,
		"delivery_kinds":        kinds,
		"has_command":           len(expansion.Command) > 0,
		"has_workspace_outputs": len(expansion.Outputs) > 0,
	}, nil
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
	projectGrant, err := parseScope(stringArg(call.Arguments, "grant_project", ""), store.GrantOnce)
	if err != nil {
		return nil, err
	}
	secretGrant, err := parseScope(stringArg(call.Arguments, "grant_secret", ""), store.GrantOnce)
	if err != nil {
		return nil, err
	}
	envRefs := stringMapArg(call.Arguments["env"])
	fileRefs := stringMapArg(call.Arguments["files"])
	target := strings.TrimSpace(stringArg(call.Arguments, "target", ""))
	expansion := store.ManifestTargetExpansion{}
	if target != "" {
		root, err := canonicalProjectRootMCPFn(ctx, projectRoot)
		if err != nil {
			return nil, err
		}
		expanded, err := brokerops.ExpandExecutionTarget(root, target, envRefs, fileRefs, command)
		if err != nil {
			return nil, err
		}
		expansion = expanded.Expansion
		envRefs = expanded.EnvRefs
		fileRefs = expanded.FileRefs
		command = expanded.Command
	}
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
	var stdoutCapture *mcpToolOutputCapture
	var stderrCapture *mcpToolOutputCapture
	execResult, err := brokerops.Execute(ctx, brokerops.ExecutionRequest{
		Handle:       handle,
		BindingID:    binding.ID,
		ProjectRoot:  projectRoot,
		SessionToken: session.Token,
		Command:      command,
		EnvRefs:      envRefs,
		FileRefs:     fileRefs,
		Expansion:    expansion,
		ProjectGrant: projectGrant,
		SecretGrant:  secretGrant,
		Window:       15 * time.Minute,
		ConfigureRunner: func(items []store.Item, input runner.Input) runner.Input {
			stdoutCapture = newMCPToolOutputCapture(items)
			stderrCapture = newMCPToolOutputCapture(items)
			input.Stdout = stdoutCapture.Writer()
			input.Stderr = stderrCapture.Writer()
			return input
		},
		Deps: brokerops.ExecutionDeps{
			AuthorizeReference: authorizeReferenceMCPFn,
			RunnerExecute:      runnerExecuteMCPFn,
		},
	})
	if err != nil {
		return nil, err
	}
	runResult := execResult.RunResult
	stdoutCapture.WriteBuffered(runResult.Stdout)
	stderrCapture.WriteBuffered(runResult.Stderr)
	stdoutCapture.Close()
	stderrCapture.Close()
	stdoutStats := stdoutCapture.Stats()
	stderrStats := stderrCapture.Stats()
	response := map[string]any{
		"exit_code":            runResult.ExitCode,
		"stdout":               stdoutCapture.String(),
		"stderr":               stderrCapture.String(),
		"stdout_truncated":     stdoutCapture.Truncated(),
		"stderr_truncated":     stderrCapture.Truncated(),
		"stdout_bytes_omitted": stdoutCapture.BytesOmitted(),
		"stderr_bytes_omitted": stderrCapture.BytesOmitted(),
		"redacted":             stdoutStats.Redacted || stderrStats.Redacted,
		"suppressed":           false,
	}
	if target != "" {
		response["target"] = expansion.TargetName
		response["manifest_hash"] = expansion.ManifestHash
	}
	return response, nil
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
	projectGrant, err := parseScope(stringArg(call.Arguments, "grant_project", ""), store.GrantOnce)
	if err != nil {
		return nil, err
	}
	secretGrant, err := parseScope(stringArg(call.Arguments, "grant_secret", ""), store.GrantOnce)
	if err != nil {
		return nil, err
	}
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

func sanitizeMCPDescription(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	value = strings.ReplaceAll(value, "<", "")
	value = strings.ReplaceAll(value, ">", "")
	value = strings.TrimSpace(value)
	if len(value) > 240 {
		return value[:240]
	}
	return value
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func openHandle(ctx context.Context) (*store.Handle, error) {
	password := os.Getenv("HASP_MASTER_PASSWORD")
	vaultStore, err := newVaultStoreFn(defaultKeyringFn())
	if err != nil {
		return nil, err
	}
	var handle *store.Handle
	if strings.TrimSpace(password) != "" {
		handle, err = vaultStore.OpenWithPassword(ctx, password)
	} else {
		handle, err = vaultStore.OpenWithConvenienceUnlock(ctx)
	}
	if err == nil && handle != nil {
		auditlog.SetHMACKey(handle.AuditHMACKey())
		auditlog.EnsureKeyedChainSeed()
	}
	return handle, err
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

type mcpToolOutputCapture struct {
	buffer *cappedBuffer
	stream *redactor.StreamingWriter
}

func newMCPToolOutputCapture(items []store.Item) *mcpToolOutputCapture {
	buffer := newCappedBuffer(mcpToolOutputByteLimit)
	return &mcpToolOutputCapture{
		buffer: buffer,
		stream: redactor.NewStreamingWriter(buffer, items),
	}
}

func (c *mcpToolOutputCapture) Writer() io.Writer {
	return c.stream
}

func (c *mcpToolOutputCapture) WriteBuffered(data []byte) {
	if len(data) == 0 {
		return
	}
	_, _ = c.stream.Write(data)
}

func (c *mcpToolOutputCapture) Close() {
	_ = c.stream.Flush()
}

func (c *mcpToolOutputCapture) String() string {
	return c.buffer.String()
}

func (c *mcpToolOutputCapture) Truncated() bool {
	return c.buffer.BytesOmitted() > 0
}

func (c *mcpToolOutputCapture) BytesOmitted() int64 {
	return c.buffer.BytesOmitted()
}

func (c *mcpToolOutputCapture) Stats() redactor.Stats {
	return c.stream.Stats()
}

type cappedBuffer struct {
	limit   int
	buf     []byte
	omitted int64
}

func newCappedBuffer(limit int) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.limit < 0 {
		b.limit = 0
	}
	remaining := b.limit - len(b.buf)
	if remaining > 0 {
		if len(p) <= remaining {
			b.buf = append(b.buf, p...)
			return len(p), nil
		}
		b.buf = append(b.buf, p[:remaining]...)
		b.omitted += int64(len(p) - remaining)
		return len(p), nil
	}
	b.omitted += int64(len(p))
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	return string(b.buf)
}

func (b *cappedBuffer) BytesOmitted() int64 {
	return b.omitted
}

func appendAuditApproval(bindingID string, itemName string) {
	log, err := newMCPAuditLogFn()
	if err != nil {
		return
	}
	log = log.WithKey(auditlog.GetHMACKey())
	_, _ = log.Append(audit.EventApprove, "agent", map[string]any{"action": "capture.write_grant", "binding_id": bindingID, "item_name": itemName})
}

func ensureProjectBindingMCP(ctx context.Context, handle *store.Handle, projectRoot string) (store.Binding, []store.VisibleReference, error) {
	binding, visible, _, err := projectcontext.Ensure(ctx, handle, projectRoot, mcpProjectContextDeps())
	return binding, visible, err
}

func requireMCPProjectAuthorization(ctx context.Context, handle *store.Handle, call toolCall, projectRoot string) (brokerops.Session, store.Binding, error) {
	grantProject := stringArg(call.Arguments, "grant_project", "")
	session := brokerops.Session{Token: defaultMCPSessionToken(call)}
	if strings.TrimSpace(session.Token) == "" {
		ensured, err := ensureSessionFn(ctx, projectRoot, "", defaultMCPHostLabel(call))
		if err != nil {
			return brokerops.Session{}, store.Binding{}, err
		}
		session = ensured
	}
	binding, _, err := ensureProjectBindingMCP(ctx, handle, projectRoot)
	if err != nil {
		return brokerops.Session{}, store.Binding{}, err
	}
	if err := requireProjectBindingMCP(binding, projectRoot); err != nil {
		return brokerops.Session{}, store.Binding{}, err
	}
	if grantProject != "" {
		scope, err := parseScope(grantProject, store.GrantOnce)
		if err != nil {
			return brokerops.Session{}, store.Binding{}, err
		}
		if _, err := grantProjectLeaseMCPFn(handle, binding.ID, session.Token, scope, 15*time.Minute); err != nil {
			return brokerops.Session{}, store.Binding{}, err
		}
	}
	decision, err := authorizeAndConsumeMCPFn(handle, store.AccessRequest{
		Operation:    store.OperationList,
		BindingID:    binding.ID,
		SessionToken: session.Token,
	})
	if err != nil {
		return brokerops.Session{}, store.Binding{}, err
	}
	if !decision.Allowed {
		return brokerops.Session{}, store.Binding{}, approvalRequired(decision.Reason)
	}
	return session, binding, nil
}

func requireProjectBindingMCP(binding store.Binding, projectRoot string) error {
	if binding.ID != "" {
		return nil
	}
	return fmt.Errorf("project %q is not managed yet; run inside a git repo with auto-protect enabled or bind it explicitly", projectRoot)
}

type projectDefaultsMCP = projectcontext.Defaults

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
	return projectcontext.CloneAliases(input)
}

func mcpProjectContextDeps() projectcontext.Deps {
	return projectcontext.Deps{
		ResolveBindingView: resolveBindingViewMCPFn,
		LoadDefaults:       loadProjectDefaultsMCP,
		CanonicalRoot:      canonicalProjectRootMCPFn,
		IsGitRepo:          pathLooksLikeGitRepoMCP,
		InstallHooks:       installHooksMCPFn,
		UpsertBinding:      upsertBindingMCPFn,
	}
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

func parseScope(value string, fallback store.GrantScope) (store.GrantScope, error) {
	switch strings.TrimSpace(value) {
	case "":
		return fallback, nil
	case string(store.GrantOnce):
		return store.GrantOnce, nil
	case string(store.GrantSession):
		return store.GrantSession, nil
	case string(store.GrantWindow):
		return store.GrantWindow, nil
	default:
		return "", fmt.Errorf("unsupported grant scope %q", value)
	}
}

func approvalRequired(reason string) error {
	switch reason {
	case "project_lease_required":
		return fmt.Errorf("approval required: %s; retry with grant_project=once|session|window to authorize the current MCP session for this project", reason)
	case "secret_session_grant_required", "access_secret_prompt_required":
		return fmt.Errorf("approval required: %s; retry with grant_secret=once|session|window when the tool supports secret grants", reason)
	default:
		return fmt.Errorf("approval required: %s", reason)
	}
}

func fmtUnsupportedTool(name string) error {
	return fmt.Errorf("unsupported tool %q", name)
}
