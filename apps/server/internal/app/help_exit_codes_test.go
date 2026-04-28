package app

// hasp-4u00: exit-code bucket table is now a discoverable help topic.

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpExitCodesTopicLandsOnRequest(t *testing.T) {
	var buf bytes.Buffer
	if err := printHelpTopic(&buf, []string{"exit-codes"}); err != nil {
		t.Fatalf("printHelpTopic exit-codes: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"E_NOT_FOUND",
		"E_VAULT_LOCKED",
		"E_DAEMON_UNREACHABLE",
		"E_REPO_LEAK",
		"6  not found",
		"3  permission",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exit-codes help missing %q", want)
		}
	}
}

func TestRootHelpReferencesExitCodesTopic(t *testing.T) {
	var buf bytes.Buffer
	if err := printHelpTopic(&buf, nil); err != nil {
		t.Fatalf("printHelpTopic root: %v", err)
	}
	if !strings.Contains(buf.String(), "hasp help exit-codes") {
		t.Fatalf("root help should reference exit-codes topic:\n%s", buf.String())
	}
}
