package app

// RED test for hasp-jp31 — incident review needs the matched item names on
// every redaction audit event. The redactor already returns
// Result.MatchedItems; this test pins the contract that exec.go's
// EventRedact emission carries that list as `redacted_items` (sorted,
// deduplicated, never the value itself).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCommandRedactionAuditIncludesMatchedItemNames(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	// Use a value that exceeds the redactor minimum length and is unlikely to
	// appear in any other audit field — that way string-search assertions on
	// the audit log surface only legitimate matches.
	if err := Run(context.Background(), []string{"set", "--name", "api_token", "--value", "sk-jp31-token-marker"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run set api_token: %v", err)
	}
	if err := Run(context.Background(), []string{"project", "bind", "--project-root", projectRoot, "--alias", "secret_01=api_token"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("project bind: %v", err)
	}

	var stdout bytes.Buffer
	if err := runCommand(context.Background(), []string{
		"--project-root", projectRoot,
		"--env", "API_TOKEN=@api_token",
		"--grant-project", "window", "--grant-secret", "session", "--grant-window", "15m",
		"--", "sh", "-c", "printf '%s' \"$API_TOKEN\"",
	}, &stdout, &stdout, starter); err != nil {
		t.Fatalf("run command: %v", err)
	}
	if strings.Contains(stdout.String(), "sk-jp31-token-marker") {
		t.Fatalf("expected redacted output, got %q", stdout.String())
	}

	// Find the redact event in the audit log and pin redacted_items.
	auditPath := filepath.Join(homeDir, "audit.jsonl")
	file, err := os.Open(auditPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	type evt struct {
		Type    string         `json:"type"`
		Details map[string]any `json:"details"`
	}
	found := false
	for scanner.Scan() {
		var e evt
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			t.Fatalf("decode audit event: %v\nline=%q", err, scanner.Text())
		}
		if e.Type != "redact" {
			continue
		}
		raw, ok := e.Details["redacted_items"]
		if !ok {
			t.Fatalf("redact event missing redacted_items: %v", e.Details)
		}
		items, ok := raw.([]any)
		if !ok {
			t.Fatalf("redacted_items has unexpected type %T: %v", raw, raw)
		}
		if len(items) == 0 {
			t.Fatalf("redacted_items is empty: %v", e.Details)
		}
		matched := false
		for _, item := range items {
			s, _ := item.(string)
			if s == "api_token" {
				matched = true
			}
			// Defense in depth: the value itself must NEVER appear in the audit log.
			if strings.Contains(s, "sk-jp31-token-marker") {
				t.Fatalf("redacted_items leaked secret value: %v", item)
			}
		}
		if !matched {
			t.Fatalf("redacted_items missing api_token: %v", items)
		}
		found = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit log: %v", err)
	}
	if !found {
		raw, _ := os.ReadFile(auditPath)
		t.Fatalf("no redact event found in audit log:\n%s", string(raw))
	}

	// And the value must not appear anywhere else in the log either.
	raw, _ := os.ReadFile(auditPath)
	if strings.Contains(string(raw), "sk-jp31-token-marker") {
		t.Fatalf("audit log contains plaintext secret value:\n%s", string(raw))
	}
}
