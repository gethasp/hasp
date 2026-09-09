package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/reposcan"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestMCPJobValidationAndConnectionFailures(t *testing.T) {
	lockMCPSeams(t)
	handle, root := setupMCPTargetFixture(t)
	originalRoot, originalEnsure, originalPaths := canonicalProjectRootMCPFn, ensureSessionFn, resolveJobPaths
	t.Cleanup(func() {
		canonicalProjectRootMCPFn, ensureSessionFn, resolveJobPaths = originalRoot, originalEnsure, originalPaths
	})
	canonicalProjectRootMCPFn = func(context.Context, string) (string, error) { return "", os.ErrPermission }
	if _, err := callJobStatus(context.Background(), toolCall{}); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("status root error: %v", err)
	}
	if _, err := callExecute(context.Background(), handle, toolCall{Name: "hasp_job_start"}); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("start root error: %v", err)
	}
	cached := context.WithValue(context.Background(), mcpSessionsKey{}, &mcpSessions{tokens: map[string]string{}})
	if _, err := ensureMCPSession(cached, toolCall{}, root); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("cached session root error: %v", err)
	}
	canonicalProjectRootMCPFn = originalRoot
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{}, os.ErrPermission
	}
	if _, err := callJobStatus(context.Background(), toolCall{Arguments: map[string]any{"project_root": root}}); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("status session error: %v", err)
	}
	ensureSessionFn = func(context.Context, string, string, string) (brokerops.Session, error) {
		return brokerops.Session{Token: "session-token"}, nil
	}
	for _, args := range []map[string]any{
		{"job_id": strings.Repeat("a", 64), "request_id": strings.Repeat("b", 32)},
		{"request_id": "invalid"},
		{"job_id": strings.Repeat("a", 64), "stdout_offset": -1.0},
		{"job_id": strings.Repeat("a", 64), "stderr_offset": 0.5},
		{"job_id": strings.Repeat("a", 64)},
	} {
		args["project_root"] = root
		if _, err := callJobStatus(context.Background(), toolCall{Arguments: args}); err == nil {
			t.Fatalf("invalid or disconnected job query accepted: %v", args)
		}
	}
	for _, args := range []map[string]any{
		{"env": "wrong-type"}, {"files": "wrong-type"},
		{"target": "server.dev", "literal_env": map[string]any{"CI": "1"}},
		{"request_id": "invalid"}, {"request_id": strings.Repeat("a", 32)},
	} {
		args["project_root"], args["command"] = root, []any{"true"}
		want := "dial"
		if _, ok := args["env"]; ok {
			want = "env must be an object"
		}
		if _, ok := args["files"]; ok {
			want = "files must be an object"
		}
		if _, ok := args["target"]; ok {
			want = "target cannot be combined"
		}
		if args["request_id"] == "invalid" {
			want = "request_id must"
		}
		if _, err := callExecute(context.Background(), handle, toolCall{Name: "hasp_job_start", Arguments: args}); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("start %v: error=%v, want %q", args, err, want)
		}
	}
	resolveJobPaths = func() (paths.Paths, error) { return paths.Paths{}, os.ErrPermission }
	if _, err := connectJobDaemon(context.Background()); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("path error: %v", err)
	}
	for _, value := range []any{-1.0, 0.5, float64(1<<53) + 2, "1", math.Inf(1), math.NaN()} {
		if _, err := jobOffset(map[string]any{"cursor": value}, "cursor"); err == nil {
			t.Fatalf("invalid cursor %v accepted", value)
		}
	}
	if err := approvalRequired("project_lease_required"); !strings.Contains(err.Error(), "grant_project=once|session|window") {
		t.Fatalf("project approval omitted: %v", err)
	}
}

func TestMCPJobReservationFailureIncludesRecoveryInstructions(t *testing.T) {
	lockMCPSeams(t)
	handle, root := setupMCPTargetFixture(t)
	token := startGrantedMCPTestSession(t, handle, root)
	resolved, err := paths.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(resolved.RuntimeDir, "jobs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err = callExecute(context.Background(), handle, toolCall{Name: "hasp_job_start", Arguments: map[string]any{
		"project_root": root, "session_token": token, "request_id": strings.Repeat("b", 32), "command": []any{"sh", "-c", "touch executed"},
	}})
	if err == nil || !strings.Contains(err.Error(), "job start response unavailable") || !strings.Contains(err.Error(), "same request_id") {
		t.Fatalf("missing recovery instruction: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "executed")); !os.IsNotExist(err) {
		t.Fatalf("child ran without durable reservation: %v", err)
	}
}

func TestMCPReportsLiteralDeliveryAndRejectsSkippedSources(t *testing.T) {
	lockMCPSeams(t)
	handle, root := setupMCPTargetFixture(t)
	token := startGrantedMCPTestSession(t, handle, root)
	manifestPath := filepath.Join(root, ".hasp.manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"name": "server.dev",`, `"name": "server.dev", "literal_env": {"CI": "1"},`, 1))
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"project_root": root, "session_token": token, "target": "server.dev"}
	listing, err := callTargets(context.Background(), handle, toolCall{Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	targets := listing["targets"].([]map[string]any)
	found := false
	for _, target := range targets {
		if target["name"] == "server.dev" {
			found = slices.Contains(target["delivery_kinds"].([]string), "literal_env")
		}
	}
	if !found {
		t.Fatalf("literal delivery omitted: %+v", listing)
	}
	detail, err := callTargetExplain(context.Background(), handle, toolCall{Arguments: args})
	if err != nil || !slices.Contains(detail["delivery_kinds"].([]string), "literal_env") {
		t.Fatalf("literal explain: %+v, %v", detail, err)
	}
	encoded, err := json.Marshal(detail)
	if err != nil || strings.Contains(string(encoded), "abc123secret") {
		t.Fatalf("explain leaked secret: %v", err)
	}
	for _, field := range []string{"staged", "fail_on_skipped"} {
		if _, err := callCheck(context.Background(), handle, toolCall{Arguments: map[string]any{field: "true"}}); err == nil {
			t.Fatalf("%s accepted a string", field)
		}
	}
	original := reposcanScanMCPFn
	t.Cleanup(func() { reposcanScanMCPFn = original })
	reposcanScanMCPFn = func(context.Context, string, []store.Item, int64, reposcan.Deps) (reposcan.Result, error) {
		return reposcan.Result{Complete: false, Skipped: []reposcan.Skipped{{Path: "large", Size: reposcan.DefaultMaxBytes + 1, Reason: "over_max_bytes"}}}, nil
	}
	args["fail_on_skipped"] = true
	result, err := callCheck(context.Background(), handle, toolCall{Arguments: args})
	if err == nil || !strings.Contains(err.Error(), "skipped without being scanned") || result["complete"] != false {
		t.Fatalf("skipped scan passed: %+v, %v", result, err)
	}
}
