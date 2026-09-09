package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDryRunReportsChecksWithoutClaimingAuthorization(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			lockAppSeams(t)
			home := filepath.Join(t.TempDir(), "uninitialized-vault")
			root := t.TempDir()
			t.Setenv("HASP_HOME", home)
			var output bytes.Buffer
			err := runCommand(context.Background(), []string{
				"--project-root", root, "--env", "TOKEN=@MISSING",
				"--grant-project", "once", "--grant-secret", "once",
				"--dry-run", "--explain-format", format,
				"--", "sh", "-c", "touch child-ran",
			}, io.Discard, &output, &fakeStarter{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(home); !os.IsNotExist(err) {
				t.Fatalf("planning created or opened a vault: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, "child-ran")); !os.IsNotExist(err) {
				t.Fatalf("planning started the child: %v", err)
			}
			if format == "text" {
				for _, want := range []string{"execution plan", "argument_syntax: passed", "reference_availability: not_checked", "runtime_authorization: not_checked", "planned for child output"} {
					if !strings.Contains(output.String(), want) {
						t.Fatalf("plan lacks %q: %s", want, output.String())
					}
				}
				return
			}
			var payload map[string]any
			if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if payload["phase"] != "plan" || payload["redactor_active"] != false || payload["redactor_planned"] != true {
				t.Fatalf("plan claims runtime state: %+v", payload)
			}
			checks, _ := payload["checks"].(map[string]any)
			for _, field := range []string{"project_binding", "reference_availability", "runtime_authorization"} {
				if checks[field] != "not_checked" {
					t.Fatalf("plan claims %s was checked: %+v", field, checks)
				}
			}
			if checks["argument_syntax"] != "passed" || checks["grant_syntax"] != "passed" || checks["command_execution"] != "not_started" {
				t.Fatalf("incorrect plan check states: %+v", checks)
			}
		})
	}
}
