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
	"sync"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/envmap"
	"github.com/gethasp/hasp/apps/server/internal/gitsafe"
	"github.com/gethasp/hasp/apps/server/internal/hooks"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/projectcontext"
	"github.com/gethasp/hasp/apps/server/internal/redactor"
	"github.com/gethasp/hasp/apps/server/internal/reposcan"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
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
	authorizeReferencesMCPFn  = brokerops.AuthorizeReferences
	authorizeAndConsumeMCPFn  = (*store.Handle).AuthorizeAndConsume
	runnerExecuteMCPFn        = runner.Execute
	reposcanScanMCPFn         = reposcan.Scan
	reposcanScanStagedMCPFn   = reposcan.ScanStaged
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
	if call.Name == "hasp_status" {
		return map[string]any{"connection": "connected", "scope": "this_mcp_transport", "client_shell_protection": "not_attested", "authorization": "not_checked"}, nil
	}
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
		return callTargetExplain(ctx, handle, call)
	case "hasp_job_status", "hasp_job_cancel":
		return callJobStatus(ctx, call)
	case "hasp_run", "hasp_inject", "hasp_job_start":
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
	session, err := ensureMCPSession(ctx, call, projectRoot)
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
		return nil, brokerops.NewAuthorizationError(handle, store.AccessRequest{Operation: store.OperationList, BindingID: binding.ID, SessionToken: session.Token}, decision)
	}
	return map[string]any{
		"visible":            visible,
		"lease_active":       true,
		"session_id":         session.Info.ID,
		"session_expires_at": session.Info.ExpiresAt,
	}, nil
}

func callCheck(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	for _, field := range []string{"staged", "fail_on_skipped"} {
		if value, present := call.Arguments[field]; present {
			if _, ok := value.(bool); !ok {
				return nil, fmt.Errorf("%s must be a boolean", field)
			}
		}
	}
	projectRoot := stringArg(call.Arguments, "project_root", defaultMCPProjectRoot())
	if _, _, err := requireMCPProjectAuthorization(ctx, handle, call, projectRoot); err != nil {
		return nil, err
	}
	root, err := canonicalProjectRootMCPFn(ctx, projectRoot)
	if err != nil {
		return nil, err
	}
	scan := reposcanScanMCPFn
	if boolArg(call.Arguments, "staged", false) {
		scan = reposcanScanStagedMCPFn
	}
	result, err := scan(ctx, root, handle.ListItems(), reposcan.DefaultMaxFileBytes, reposcan.Deps{})
	payload := map[string]any{"matches": result.Matches, "skipped": result.Skipped, "walker": result.Walker, "complete": result.Complete, "deleted": result.Deleted, "issues": result.Issues, "stats": result.Stats}
	if err == nil && boolArg(call.Arguments, "fail_on_skipped", false) && len(result.Skipped) > 0 {
		err = fmt.Errorf("%d source(s) skipped without being scanned", len(result.Skipped))
	}
	if err != nil {
		payload["complete"] = false
		payload["error"] = map[string]any{"code": "E_SCAN_INCOMPLETE", "message": err.Error()}
		return payload, err
	}
	return payload, nil
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
		sets := make([]string, 0)
		prereqs := make([]map[string]any, 0, len(target.Delivery))
		if len(target.LiteralEnv) > 0 {
			kinds = append(kinds, "literal_env")
		}
		for _, delivery := range target.Delivery {
			ref, _ := manifest.DeliveryRef(delivery)
			refs = append(refs, ref)
			kinds = append(kinds, delivery.As)
			if set, ok := manifest.DeliveryCredentialSet(delivery); ok {
				sets = append(sets, set.Name)
			}
			_, err := handle.ResolveReference(ctx, root, ref)
			prereq := map[string]any{
				"ref":     ref,
				"kind":    delivery.As,
				"present": err == nil,
			}
			if set, ok := manifest.DeliveryCredentialSet(delivery); ok {
				prereq["credential_set"] = set.Name
				prereq["role"] = strings.TrimSpace(delivery.Role)
			}
			prereqs = append(prereqs, prereq)
		}
		targets = append(targets, map[string]any{
			"name":              target.Name,
			"description":       sanitizeMCPDescription(target.Description),
			"refs":              uniqueStrings(refs),
			"credential_sets":   uniqueStrings(sets),
			"delivery_kinds":    uniqueStrings(kinds),
			"prerequisites":     prereqs,
			"literal_env_names": envmap.Names(target.LiteralEnv),
		})
	}
	return map[string]any{"manifest_hash": identity, "targets": targets}, nil
}

func callTargetExplain(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	projectRoot := stringArg(call.Arguments, "project_root", defaultMCPProjectRoot())
	targetName := strings.TrimSpace(stringArg(call.Arguments, "target", ""))
	if targetName == "" {
		return nil, errors.New("target is required")
	}
	// Require the project to be hasp-managed before exposing its manifest's secret
	// aliases / destinations. This is a light binding check (no approval prompt, no
	// grant consumption) so onboarding isn't disrupted, but an unauthorized agent
	// can no longer enumerate any project_root's manifest structure (hasp-adm3).
	binding, _, err := ensureProjectBindingMCP(ctx, handle, projectRoot)
	if err != nil {
		return nil, err
	}
	if err := requireProjectBindingMCP(binding, projectRoot); err != nil {
		return nil, err
	}
	root, err := canonicalProjectRootMCPFn(ctx, projectRoot)
	if err != nil {
		return nil, err
	}
	expansion, err := store.ExpandManifestTarget(root, targetName)
	if err != nil {
		return nil, err
	}
	kinds := make([]string, 0, 4)
	if len(expansion.LiteralEnv) > 0 {
		kinds = append(kinds, "literal_env")
	}
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
		"credential_sets":       expansion.CredentialSets,
		"destinations":          expansion.Destinations,
		"literal_env_names":     envmap.Names(expansion.LiteralEnv),
		"delivery_kinds":        kinds,
		"has_command":           len(expansion.Command) > 0,
		"has_workspace_outputs": len(expansion.Outputs) > 0,
	}, nil
}

func callExecute(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	projectRoot := stringArg(call.Arguments, "project_root", defaultMCPProjectRoot())
	if call.Name == "hasp_job_start" {
		root, err := canonicalProjectRootMCPFn(ctx, projectRoot)
		if err != nil {
			return nil, err
		}
		projectRoot = root
	}
	session, err := ensureMCPSession(ctx, call, projectRoot)
	if err != nil {
		return nil, err
	}
	command := stringSliceArg(call.Arguments["command"])
	if len(command) == 0 {
		return nil, errors.New("command is required")
	}
	projectGrant, err := parseScope(stringArg(call.Arguments, "grant_project", ""), "")
	if err != nil {
		return nil, err
	}
	secretGrant, err := parseScope(stringArg(call.Arguments, "grant_secret", ""), "")
	if err != nil {
		return nil, err
	}
	envRefs, err := executionMapArg(call.Arguments, "env")
	if err != nil {
		return nil, err
	}
	fileRefs, err := executionMapArg(call.Arguments, "files")
	if err != nil {
		return nil, err
	}
	literalEnv, err := executionMapArg(call.Arguments, "literal_env")
	if err != nil {
		return nil, err
	}
	target := strings.TrimSpace(stringArg(call.Arguments, "target", ""))
	expansion := store.ManifestTargetExpansion{}
	if target != "" {
		if len(literalEnv) > 0 {
			return nil, errors.New("target cannot be combined with explicit literal_env mappings")
		}
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
		literalEnv = expanded.LiteralEnv
		command = expanded.Command
	}
	if err := envmap.Validate(envRefs, fileRefs, literalEnv); err != nil {
		return nil, err
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
	var jobClient *runtime.Client
	var jobRequest runtime.JobStartRequest
	var jobStatus runtime.JobStatus
	if call.Name == "hasp_job_start" {
		requestID := stringArg(call.Arguments, "request_id", "")
		id, err := runtime.JobID(projectRoot, requestID)
		if err != nil {
			return nil, err
		}
		fingerprint := jobFingerprint(command, envRefs, fileRefs, literalEnv, expansion.ExecutionRoot(projectRoot), expansion.ManifestHash)
		jobClient, err = connectJobDaemon(ctx)
		if err != nil {
			return nil, err
		}
		defer jobClient.Close()
		existing, err := jobClient.GetJob(ctx, runtime.JobQuery{SessionToken: session.Token, ProjectRoot: projectRoot, JobID: id, Fingerprint: fingerprint})
		if err != nil {
			return nil, err
		}
		if existing.State != "not_found" {
			return jobPayload(existing), nil
		}
		jobRequest = runtime.JobStartRequest{SessionToken: session.Token, ProjectRoot: projectRoot, RequestID: requestID, Fingerprint: fingerprint, ParentEnv: runner.InheritedEnv()}
	}
	runnerExecute := runnerExecuteMCPFn
	if jobClient != nil {
		runnerExecute = func(ctx context.Context, input runner.Input) (runner.Result, error) {
			jobRequest.WorkingDir, jobRequest.Command, jobRequest.Env, jobRequest.Files = input.ProjectRoot, input.Command, input.Env, input.Files
			var err error
			jobStatus, err = jobClient.StartJob(ctx, jobRequest)
			if err != nil {
				return runner.Result{}, fmt.Errorf("job start response unavailable: %w; recover with hasp_job_status using the same request_id before requesting new work", err)
			}
			return runner.Result{}, nil
		}
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
		LiteralEnv:   literalEnv,
		Expansion:    expansion,
		ProjectGrant: projectGrant,
		SecretGrant:  secretGrant,
		Window:       15 * time.Minute,
		ConfigureRunner: func(items []store.Item, input runner.Input) runner.Input {
			if jobClient != nil {
				jobRequest.Items = items
				return input
			}
			stdoutCapture = newMCPToolOutputCapture(items)
			stderrCapture = newMCPToolOutputCapture(items)
			input.Stdout = stdoutCapture.Writer()
			input.Stderr = stderrCapture.Writer()
			return input
		},
		Deps: brokerops.ExecutionDeps{
			AuthorizeReferences: authorizeReferencesMCPFn,
			RunnerExecute:       runnerExecute,
		},
	})
	if err != nil {
		return nil, err
	}
	if jobClient != nil {
		return jobPayload(jobStatus), nil
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
	session, err := ensureMCPSession(ctx, call, projectRoot)
	if err != nil {
		return nil, err
	}
	name := stringArg(call.Arguments, "name", "")
	kind := store.ItemKind(stringArg(call.Arguments, "kind", string(store.ItemKindKV)))
	value := stringArg(call.Arguments, "value", "")
	bind := boolArg(call.Arguments, "bind", false)
	projectGrant, err := parseScope(stringArg(call.Arguments, "grant_project", ""), "")
	if err != nil {
		return nil, err
	}
	secretGrant, err := parseScope(stringArg(call.Arguments, "grant_secret", ""), "")
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

type mcpSessionTokenSource int

const (
	mcpSessionTokenNone mcpSessionTokenSource = iota
	mcpSessionTokenExplicit
	mcpSessionTokenEnv
)

func defaultMCPSessionToken(call toolCall) string {
	token, _ := mcpSessionToken(call)
	return token
}

func mcpSessionToken(call toolCall) (string, mcpSessionTokenSource) {
	if value, ok := call.Arguments["session_token"]; ok {
		text, _ := value.(string)
		token := strings.TrimSpace(text)
		if token == "" {
			return "", mcpSessionTokenNone
		}
		return token, mcpSessionTokenExplicit
	}
	if token := strings.TrimSpace(os.Getenv(mcpEnvSessionToken)); token != "" {
		return token, mcpSessionTokenEnv
	}
	return "", mcpSessionTokenNone
}

func ensureMCPSession(ctx context.Context, call toolCall, projectRoot string) (brokerops.Session, error) {
	token, source := mcpSessionToken(call)
	sessions, _ := ctx.Value(mcpSessionsKey{}).(*mcpSessions)
	var root string
	if sessions != nil && source != mcpSessionTokenExplicit {
		var err error
		root, err = canonicalProjectRootMCPFn(ctx, projectRoot)
		if err != nil {
			return brokerops.Session{}, err
		}
		sessions.mu.Lock()
		defer sessions.mu.Unlock()
		if cached := sessions.tokens[root]; cached != "" {
			token = cached
		}
	}
	hostLabel := defaultMCPHostLabel(call)
	session, err := ensureSessionFn(ctx, projectRoot, token, hostLabel)
	if isRecoverableInheritedSessionError(err) {
		if source == mcpSessionTokenExplicit {
			return brokerops.Session{}, fmt.Errorf("%w; explicit session_token is stale or bound to another project, omit session_token to let MCP open a fresh local session", err)
		}
		if sessions != nil {
			delete(sessions.tokens, root)
		}
		session, err = ensureSessionFn(ctx, projectRoot, "", hostLabel)
	}
	if err != nil {
		return brokerops.Session{}, err
	}
	if sessions != nil && source != mcpSessionTokenExplicit {
		sessions.tokens[root] = session.Token
	}
	return session, nil
}

type mcpSessionsKey struct{}

// One cache belongs to one MCP connection. Every reuse is resolved by the
// daemon; replacing an expired token never copies the old session's grants.
type mcpSessions struct {
	mu     sync.Mutex
	tokens map[string]string
}

func isRecoverableInheritedSessionError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "resolve session:") && strings.Contains(message, "session not found") ||
		strings.Contains(message, "session project root mismatch:")
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
	session, err := ensureMCPSession(ctx, call, projectRoot)
	if err != nil {
		return brokerops.Session{}, store.Binding{}, err
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
		return brokerops.Session{}, store.Binding{}, brokerops.NewAuthorizationError(handle, store.AccessRequest{Operation: store.OperationList, BindingID: binding.ID, SessionToken: session.Token}, decision)
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
	if !info.IsDir() && !info.Mode().IsRegular() {
		return false
	}
	_, err = gitsafe.TopLevel(context.Background(), root)
	return err == nil
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

func executionMapArg(args map[string]any, key string) (map[string]string, error) {
	value, exists := args[key]
	if !exists {
		return nil, nil
	}
	source, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object of string values", key)
	}
	result := make(map[string]string, len(source))
	for name, value := range source {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s value for %q must be a string", key, name)
		}
		result[name] = text
	}
	return result, nil
}
