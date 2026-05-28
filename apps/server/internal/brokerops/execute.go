package brokerops

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type ExecutionDeps struct {
	AuthorizeReference func(ctx context.Context, handle *store.Handle, bindingID, projectRoot, sessionToken, reference string, op store.Operation, projScope, secScope, convScope store.GrantScope, window time.Duration, dest string) (store.Item, error)
	RunnerExecute      func(ctx context.Context, input runner.Input) (runner.Result, error)
}

type ExecutionTarget struct {
	Expansion store.ManifestTargetExpansion
	EnvRefs   map[string]string
	FileRefs  map[string]string
	Command   []string
}

type ExecutionRequest struct {
	Handle           *store.Handle
	BindingID        string
	ProjectRoot      string
	SessionToken     string
	Command          []string
	EnvRefs          map[string]string
	FileRefs         map[string]string
	Expansion        store.ManifestTargetExpansion
	ProjectGrant     store.GrantScope
	SecretGrant      store.GrantScope
	Window           time.Duration
	RunnerInput      runner.Input
	AuthorizeWrapErr func(error) error
	ConfigureRunner  func(items []store.Item, input runner.Input) runner.Input
	Deps             ExecutionDeps
}

type ExecutionResult struct {
	RunResult runner.Result
	Items     []store.Item
}

type TargetReviewRequiredError struct {
	Target string
	Drift  store.ManifestDrift
}

func (e TargetReviewRequiredError) Error() string {
	target := e.Target
	if target == "" {
		target = "(unknown)"
	}
	reason := "requires local review"
	if e.Drift.Changed {
		reason = "requires renewed local review after manifest changes"
	}
	return fmt.Sprintf("manifest target %q %s; inspect the value-free target shape, then run `hasp project target review %s`", target, reason, target)
}

func ExpandExecutionTarget(projectRoot string, targetName string, envRefs map[string]string, fileRefs map[string]string, command []string) (ExecutionTarget, error) {
	out := ExecutionTarget{
		EnvRefs:  cloneStringMap(envRefs),
		FileRefs: cloneStringMap(fileRefs),
		Command:  append([]string(nil), command...),
	}
	if targetName == "" {
		return out, nil
	}
	if len(envRefs) > 0 || len(fileRefs) > 0 {
		return out, errors.New("target cannot be combined with explicit env or files mappings")
	}
	expansion, err := store.ExpandManifestTarget(projectRoot, targetName)
	if err != nil {
		return out, err
	}
	if len(expansion.XCConfig) > 0 || len(expansion.Outputs) > 0 {
		return out, fmt.Errorf("target %q contains workspace-visible delivery; use hasp write-env --target", targetName)
	}
	out.Expansion = expansion
	out.EnvRefs = cloneStringMap(expansion.Env)
	out.FileRefs = cloneStringMap(expansion.Files)
	if len(out.Command) == 0 && len(expansion.Command) > 0 {
		out.Command = append([]string(nil), expansion.Command...)
	}
	return out, nil
}

func Execute(ctx context.Context, request ExecutionRequest) (ExecutionResult, error) {
	deps := request.Deps
	if deps.AuthorizeReference == nil {
		deps.AuthorizeReference = AuthorizeReference
	}
	if deps.RunnerExecute == nil {
		deps.RunnerExecute = runner.Execute
	}
	if err := RequireReviewedTarget(request.Handle, request.ProjectRoot, request.Expansion); err != nil {
		return ExecutionResult{}, err
	}

	items := make([]store.Item, 0, len(request.EnvRefs)+len(request.FileRefs))
	env := map[string]string{}
	files := map[string][]byte{}
	for envName, reference := range request.EnvRefs {
		item, err := deps.AuthorizeReference(ctx, request.Handle, request.BindingID, request.ProjectRoot, request.SessionToken, reference, store.OperationRun, request.ProjectGrant, request.SecretGrant, "", request.Window, "")
		if err != nil {
			return ExecutionResult{}, wrapExecutionAuthorizeError(request, err)
		}
		env[envName] = string(item.Value)
		items = append(items, item)
	}
	for envName, reference := range request.FileRefs {
		item, err := deps.AuthorizeReference(ctx, request.Handle, request.BindingID, request.ProjectRoot, request.SessionToken, reference, store.OperationInject, request.ProjectGrant, request.SecretGrant, "", request.Window, "")
		if err != nil {
			return ExecutionResult{}, wrapExecutionAuthorizeError(request, err)
		}
		files[envName] = item.Value
		items = append(items, item)
	}

	input := request.RunnerInput
	input.ProjectRoot = request.Expansion.ExecutionRoot(request.ProjectRoot)
	input.Command = append([]string(nil), request.Command...)
	input.Env = env
	input.Files = files
	if request.ConfigureRunner != nil {
		input = request.ConfigureRunner(items, input)
	}
	runResult, err := deps.RunnerExecute(ctx, input)
	if err != nil {
		return ExecutionResult{}, err
	}
	return ExecutionResult{RunResult: runResult, Items: items}, nil
}

func RequireReviewedTarget(handle *store.Handle, projectRoot string, expansion store.ManifestTargetExpansion) error {
	if expansion.TargetName == "" {
		return nil
	}
	if handle == nil {
		return TargetReviewRequiredError{Target: expansion.TargetName}
	}
	drift, err := handle.ManifestTargetDrift(projectRoot, expansion)
	if err != nil {
		return err
	}
	if !drift.Known || drift.Changed {
		return TargetReviewRequiredError{Target: expansion.TargetName, Drift: drift}
	}
	return nil
}

func wrapExecutionAuthorizeError(request ExecutionRequest, err error) error {
	if request.AuthorizeWrapErr == nil {
		return err
	}
	return request.AuthorizeWrapErr(err)
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
