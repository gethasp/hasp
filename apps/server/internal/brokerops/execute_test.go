package brokerops

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestExpandExecutionTargetHandlesExplicitAndManifestTargets(t *testing.T) {
	explicitEnv := map[string]string{"TOKEN": "secret_01"}
	explicitFiles := map[string]string{"CONFIG": "file_01"}
	target, err := ExpandExecutionTarget("", "", explicitEnv, explicitFiles, []string{"echo", "ok"})
	if err != nil {
		t.Fatalf("explicit target: %v", err)
	}
	explicitEnv["TOKEN"] = "changed"
	explicitFiles["CONFIG"] = "changed"
	if target.EnvRefs["TOKEN"] != "secret_01" || target.FileRefs["CONFIG"] != "file_01" {
		t.Fatalf("explicit maps were not cloned: %+v", target)
	}
	if !reflect.DeepEqual(target.Command, []string{"echo", "ok"}) {
		t.Fatalf("command = %#v", target.Command)
	}

	projectRoot := t.TempDir()
	writeBrokeropsManifest(t, projectRoot, `{
	  "version":"v1",
	  "references":[{"alias":"secret_01","item":"api_token"},{"alias":"file_01","item":"config_file"}],
	  "requirements":[
	    {"ref":"secret_01","kind":"kv","classification":"secret"},
	    {"ref":"file_01","kind":"file","classification":"secret"}
	  ],
	  "targets":[{"name":"server.dev","root":"cmd/server","command":["go","run","."],"delivery":[
	    {"as":"env","name":"API_TOKEN","ref":"secret_01"},
	    {"as":"file","name":"CONFIG_FILE","ref":"file_01"}
	  ]}]
	}`)
	target, err = ExpandExecutionTarget(projectRoot, "server.dev", nil, nil, nil)
	if err != nil {
		t.Fatalf("manifest target: %v", err)
	}
	if target.EnvRefs["API_TOKEN"] != "secret_01" || target.FileRefs["CONFIG_FILE"] != "file_01" {
		t.Fatalf("manifest refs = %+v", target)
	}
	if !reflect.DeepEqual(target.Command, []string{"go", "run", "."}) {
		t.Fatalf("manifest command = %#v", target.Command)
	}

	override, err := ExpandExecutionTarget(projectRoot, "server.dev", nil, nil, []string{"custom"})
	if err != nil {
		t.Fatalf("manifest target with command override: %v", err)
	}
	if !reflect.DeepEqual(override.Command, []string{"custom"}) {
		t.Fatalf("override command = %#v", override.Command)
	}
}

func TestExpandExecutionTargetRejectsUnsafeCombinations(t *testing.T) {
	projectRoot := t.TempDir()
	writeBrokeropsManifest(t, projectRoot, `{
	  "version":"v1",
	  "references":[{"alias":"secret_01","item":"api_token"}],
	  "requirements":[{"ref":"secret_01","kind":"kv","classification":"secret"}],
	  "targets":[{"name":"xcode.config","delivery":[{"as":"xcconfig","name":"API_TOKEN","ref":"secret_01","output":"Config/Secrets.xcconfig"}]}]
	}`)

	if _, err := ExpandExecutionTarget(projectRoot, "xcode.config", map[string]string{"TOKEN": "secret_01"}, nil, nil); err == nil {
		t.Fatal("expected explicit env plus target to fail")
	}
	if _, err := ExpandExecutionTarget(projectRoot, "xcode.config", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "workspace-visible delivery") {
		t.Fatalf("expected workspace-visible delivery error, got %v", err)
	}
	if _, err := ExpandExecutionTarget(t.TempDir(), "missing", nil, nil, nil); err == nil {
		t.Fatal("expected missing manifest error")
	}
}

func TestExecuteAuthorizesRefsConfiguresRunnerAndRuns(t *testing.T) {
	var authorized []string
	var captured runner.Input
	result, err := Execute(context.Background(), ExecutionRequest{
		BindingID:    "binding",
		ProjectRoot:  "/repo",
		SessionToken: "session",
		Command:      []string{"printenv"},
		EnvRefs:      map[string]string{"TOKEN": "secret_01"},
		FileRefs:     map[string]string{"CONFIG": "file_01"},
		Expansion:    store.ManifestTargetExpansion{TargetRoot: "subdir"},
		ProjectGrant: store.GrantWindow,
		SecretGrant:  store.GrantSession,
		Window:       time.Minute,
		RunnerInput:  runner.Input{},
		ConfigureRunner: func(items []store.Item, input runner.Input) runner.Input {
			if len(items) != 2 {
				t.Fatalf("items = %+v, want 2", items)
			}
			input.Command = append(input.Command, "--configured")
			return input
		},
		Deps: ExecutionDeps{
			AuthorizeReference: func(_ context.Context, _ *store.Handle, _, _, _, reference string, op store.Operation, _, _ store.GrantScope, _ store.GrantScope, _ time.Duration, _ string) (store.Item, error) {
				authorized = append(authorized, string(op)+":"+reference)
				return store.Item{Name: reference, Value: []byte("value-" + reference)}, nil
			},
			RunnerExecute: func(_ context.Context, input runner.Input) (runner.Result, error) {
				captured = input
				return runner.Result{ExitCode: 7, Stdout: []byte("ok")}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.RunResult.ExitCode != 7 || string(result.RunResult.Stdout) != "ok" || len(result.Items) != 2 {
		t.Fatalf("result = %+v", result)
	}
	if !reflect.DeepEqual(authorized, []string{"run:secret_01", "inject:file_01"}) {
		t.Fatalf("authorized = %#v", authorized)
	}
	if captured.ProjectRoot != filepath.Join("/repo", "subdir") {
		t.Fatalf("project root = %q", captured.ProjectRoot)
	}
	if captured.Env["TOKEN"] != "value-secret_01" || string(captured.Files["CONFIG"]) != "value-file_01" {
		t.Fatalf("captured input = %+v", captured)
	}
	if !reflect.DeepEqual(captured.Command, []string{"printenv", "--configured"}) {
		t.Fatalf("command = %#v", captured.Command)
	}
}

func TestExecuteWrapsAuthorizationErrorsAndPropagatesRunnerErrors(t *testing.T) {
	wrapped := errors.New("wrapped")
	_, err := Execute(context.Background(), ExecutionRequest{
		EnvRefs: map[string]string{"TOKEN": "secret_01"},
		AuthorizeWrapErr: func(error) error {
			return wrapped
		},
		Deps: ExecutionDeps{
			AuthorizeReference: func(context.Context, *store.Handle, string, string, string, string, store.Operation, store.GrantScope, store.GrantScope, store.GrantScope, time.Duration, string) (store.Item, error) {
				return store.Item{}, errors.New("denied")
			},
		},
	})
	if !errors.Is(err, wrapped) {
		t.Fatalf("Execute auth err = %v, want wrapped", err)
	}

	rawErr := errors.New("raw denied")
	_, err = Execute(context.Background(), ExecutionRequest{
		EnvRefs: map[string]string{"TOKEN": "secret_01"},
		Deps: ExecutionDeps{
			AuthorizeReference: func(context.Context, *store.Handle, string, string, string, string, store.Operation, store.GrantScope, store.GrantScope, store.GrantScope, time.Duration, string) (store.Item, error) {
				return store.Item{}, rawErr
			},
		},
	})
	if !errors.Is(err, rawErr) {
		t.Fatalf("Execute raw auth err = %v, want rawErr", err)
	}

	fileErr := errors.New("file denied")
	_, err = Execute(context.Background(), ExecutionRequest{
		FileRefs: map[string]string{"CONFIG": "file_01"},
		Deps: ExecutionDeps{
			AuthorizeReference: func(context.Context, *store.Handle, string, string, string, string, store.Operation, store.GrantScope, store.GrantScope, store.GrantScope, time.Duration, string) (store.Item, error) {
				return store.Item{}, fileErr
			},
		},
	})
	if !errors.Is(err, fileErr) {
		t.Fatalf("Execute file auth err = %v, want fileErr", err)
	}

	runnerErr := errors.New("runner failed")
	_, err = Execute(context.Background(), ExecutionRequest{
		Deps: ExecutionDeps{
			RunnerExecute: func(context.Context, runner.Input) (runner.Result, error) {
				return runner.Result{}, runnerErr
			},
		},
	})
	if !errors.Is(err, runnerErr) {
		t.Fatalf("Execute runner err = %v, want runnerErr", err)
	}
}

func writeBrokeropsManifest(t *testing.T, root string, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".hasp.manifest.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}
