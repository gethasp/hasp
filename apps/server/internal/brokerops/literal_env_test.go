package brokerops

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestLiteralEnvironmentPreservesBytesAndAuthorizesBeforeChild(t *testing.T) {
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_SOCKET", "")
	literals := map[string]string{"CI": "1", "EMPTY": "", "EXACT": " \n@TOKEN=$HOME=a=b "}
	authorized := false
	request := ExecutionRequest{Command: []string{"sh", "-c", `test "$CI" = 1 && test "${EMPTY+x}" = x && test -z "$EMPTY" && printf '%s' "$EXACT"`}, LiteralEnv: literals, Deps: ExecutionDeps{AuthorizeReferences: func(_ context.Context, _ *store.Handle, _, _, _ string, refs []ReferenceAccess, _, _ store.GrantScope, _ time.Duration) ([]store.Item, error) {
		authorized = true
		if len(refs) != 0 {
			t.Fatal("literal was resolved as a secret")
		}
		return nil, nil
	}, RunnerExecute: func(ctx context.Context, input runner.Input) (runner.Result, error) {
		if !authorized {
			t.Fatal("child before authorization")
		}
		return runner.Execute(ctx, input)
	}}}
	result, err := Execute(context.Background(), request)
	if err != nil || result.RunResult.ExitCode != 0 || string(result.RunResult.Stdout) != literals["EXACT"] {
		t.Fatalf("literal child failed: %+v %v", result, err)
	}
	if !reflect.DeepEqual(literals, request.LiteralEnv) {
		t.Fatal("literal map changed")
	}
	for _, test := range []struct{ env, files, literal map[string]string }{
		{map[string]string{"CI": "@TOKEN"}, nil, literals},
		{nil, map[string]string{"CI": "@TOKEN"}, literals},
		{map[string]string{"KEY": "@TOKEN"}, map[string]string{"KEY": "@TOKEN"}, nil},
		{nil, nil, map[string]string{"HASP_AGENT_SAFE_MODE": "0"}},
		{nil, nil, map[string]string{"KEY": "x\x00y"}},
		{map[string]string{"BAD=NAME": "@TOKEN"}, nil, nil},
	} {
		authorized = false
		request.EnvRefs, request.FileRefs, request.LiteralEnv = test.env, test.files, test.literal
		_, err := Execute(context.Background(), request)
		if err == nil || authorized {
			t.Fatalf("invalid maps reached authorization: err=%v authorized=%v", err, authorized)
		}
	}
}

func TestManifestLiteralEnvRequiresReviewForExactValueChanges(t *testing.T) {
	root := t.TempDir()
	handle := newBrokeropsHandle(t)
	manifest := store.RepoManifest{Version: "v1", References: []store.ManifestReference{}, Targets: []store.ManifestTarget{{Name: "config", LiteralEnv: map[string]string{"CI": "1", "VALUE": "public config", "EXACT": " value "}}}}
	write := func() {
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, ".hasp.manifest.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	target, err := ExpandExecutionTarget(root, "config", nil, nil, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Expansion.Refs) != 0 || target.LiteralEnv["EXACT"] != " value " {
		t.Fatalf("bad expansion: %+v", target)
	}
	if err := handle.RecordManifestTargetReview(root, target.Expansion); err != nil {
		t.Fatal(err)
	}
	manifest.Targets[0].LiteralEnv["EXACT"] = "value"
	write()
	changed, err := ExpandExecutionTarget(root, "config", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	drift, err := handle.ManifestTargetDrift(root, changed.Expansion)
	if err != nil || !drift.Changed || !drift.DeliveryChanged {
		t.Fatalf("literal whitespace did not invalidate review: %+v %v", drift, err)
	}
	manifest.Targets[0].LiteralEnv["PATH"] = "/tmp"
	write()
	if _, err := ExpandExecutionTarget(root, "config", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe target literal accepted: %v", err)
	}
	delete(manifest.Targets[0].LiteralEnv, "PATH")
	manifest.References = []store.ManifestReference{{Alias: "token", Item: "TOKEN"}}
	manifest.Requirements = []store.ManifestRequirement{{Ref: "token", Kind: store.ItemKindKV, Classification: store.ManifestClassificationSecret}}
	manifest.Targets[0].Delivery = []store.ManifestDelivery{{As: store.ManifestDeliveryEnv, Name: "CI", Ref: "token"}}
	write()
	if _, err := ExpandExecutionTarget(root, "config", nil, nil, nil); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("ambiguous target destination accepted: %v", err)
	}
}

func TestManifestLiteralMapCannotContainAuthorityObjects(t *testing.T) {
	for _, body := range []string{
		`{"version":"v1","references":[],"targets":[{"name":"config","literal_env":null}]}`,
		`{"version":"v1","references":[],"targets":[{"name":"config","literal_env":{"CI":null}}]}`,
		`{"version":"v1","references":[],"targets":[{"name":"config","literal_env":{"CI":1}}]}`,
		`{"version":"v1","references":[],"targets":[{"name":"config","literal_env":{"GRANTS":{"allow":true}}}]}`,
		`{"version":"v1","references":[],"literal_env":{"grants":"allow"}}`,
	} {
		if _, err := store.DecodeRepoManifest("", []byte(body)); err == nil {
			t.Fatalf("invalid literal or authority map accepted: %s", body)
		}
	}
}
