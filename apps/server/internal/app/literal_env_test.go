package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/gethasp/hasp/apps/server/internal/store"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiteralEnvDryRunListsNamesAndRejectsAmbiguity(t *testing.T) {
	var output bytes.Buffer
	err := executeCommandWithDeps(context.Background(), []string{"--dry-run", "--explain-format", "json", "--literal-env", "CI=1", "--literal-env", "EXACT=  @TOKEN=$HOME=a=b ", "--literal-env", "EMPTY=", "--", "true"}, io.Discard, &output, false, nil, execDeps{})
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(output.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	names, ok := plan["literal_env_names"].([]any)
	if !ok || len(names) != 3 || strings.Contains(output.String(), "@TOKEN") || strings.Contains(output.String(), "$HOME") {
		t.Fatalf("plan leaked literals or lost names: %s", output.String())
	}
	for _, args := range [][]string{
		{"--literal-env", "CI=1", "--literal-env", "CI=2"},
		{"--literal-env", "CI=1", "--env", "CI=@TOKEN"},
		{"--literal-env", "CI=1", "--target", "config"},
		{"--literal-env", "BAD NAME=x"},
		{"--literal-env", "HASP_SESSION_TOKEN=x"},
	} {
		err := executeCommandWithDeps(context.Background(), append([]string{"--dry-run"}, args...), io.Discard, io.Discard, false, nil, execDeps{})
		if err == nil {
			t.Fatalf("accepted invalid plan: %v", args)
		}
	}
}

func TestLiteralEnvTextPlanAndWriteEnvBoundary(t *testing.T) {
	var output bytes.Buffer
	if err := executeCommandWithDeps(context.Background(), []string{"--dry-run", "--literal-env", "CI=1", "--", "true"}, io.Discard, &output, false, nil, execDeps{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "literal env names: CI") || strings.Contains(output.String(), "CI=1") {
		t.Fatalf("plan: %s", output.String())
	}
	root := t.TempDir()
	manifest := `{"version":"v1","project":{"name":"fixture"},"targets":[{"name":"build","root":".","command":["true"],"literal_env":{"CI":"1"}}]}`
	if err := os.WriteFile(filepath.Join(root, ".hasp.manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeEnvCommandWithDeps(context.Background(), []string{"--project-root", root, "--target", "build"}, io.Discard, io.Discard, nil, execDeps{})
	if err == nil || !strings.Contains(err.Error(), "contains literal_env") {
		t.Fatalf("write-env accepted runtime literals: %v", err)
	}
}

func TestAppMappingsRejectCollisionsBeforeSaving(t *testing.T) {
	lockAppSeams(t)
	handle, root, _ := seedAppVaultHandle(t)
	cfg := appConnectConfig{Name: "collision", ProjectRoot: root, Command: "true", EnvMappings: mappingFlag{"TOKEN": "api_token"}, LiteralEnv: map[string]string{"TOKEN": "literal"}}
	if _, _, err := connectAppConsumerWithHandle(context.Background(), handle, cfg, nil, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "TOKEN") {
		t.Fatalf("ambiguous mapping saved: %v", err)
	}
	if _, err := handle.GetAppConsumer(cfg.Name); !errors.Is(err, store.ErrConsumerNotFound) {
		t.Fatalf("invalid app was persisted: %v", err)
	}
	for _, tc := range []struct {
		name, want string
		bindings   []store.AppBinding
		dotenv     string
	}{
		{"duplicate", "duplicate", []store.AppBinding{{Delivery: store.AppDeliveryEnv, Target: "TOKEN"}, {Delivery: store.AppDeliveryEnv, Target: "TOKEN"}}, ""},
		{"dotenv-name", "BAD NAME", []store.AppBinding{{Delivery: store.AppDeliveryTempDotenv, Target: "BAD NAME"}}, "ENV_FILE"},
		{"dotenv-file-collision", "duplicate", []store.AppBinding{{Delivery: store.AppDeliveryTempFile, Target: "ENV_FILE", SecretName: "api_token"}, {Delivery: store.AppDeliveryTempDotenv, Target: "TOKEN", SecretName: "api_token"}}, "ENV_FILE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateAppMappings(store.AppConsumer{Bindings: tc.bindings, DotenvEnv: tc.dotenv}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid mapping: %v", err)
			}
		})
	}
}

func TestAppReferencesResolveAliasesWithinProject(t *testing.T) {
	lockAppSeams(t)
	handle, root, _ := seedAppVaultHandle(t)
	cfg := appConnectConfig{ProjectRoot: root, EnvMappings: mappingFlag{"TOKEN": "secret_01"}, FileMappings: mappingFlag{"TOKEN_FILE": "secret_01"}, DotenvMappings: mappingFlag{"TOKEN": "secret_01"}}
	if err := normalizeAppReferences(context.Background(), handle, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, m := range []mappingFlag{cfg.EnvMappings, cfg.FileMappings, cfg.DotenvMappings} {
		for dest, item := range m {
			if item != "api_token" {
				t.Fatalf("%s resolved to %s", dest, item)
			}
		}
	}
	cfg.EnvMappings = mappingFlag{"TOKEN": "missing_alias"}
	if err := normalizeAppReferences(context.Background(), handle, &cfg); err == nil {
		t.Fatal("unknown project alias resolved")
	}
}
