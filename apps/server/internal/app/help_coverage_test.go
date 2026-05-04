package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestHelpTopicsCoverPublishedTopics(t *testing.T) {
	topics := []struct {
		args    []string
		mustSee string
	}{
		{nil, "Core concepts"},
		{[]string{"init"}, "Create the local encrypted vault"},
		{[]string{"setup"}, "Guide a user through machine setup"},
		{[]string{"bootstrap"}, "Configure a repo and an agent profile"},
		{[]string{"import"}, "Import secrets from a .env file"},
		{[]string{"set"}, "Add or replace one secret"},
		{[]string{"capture"}, "Save a value into the vault"},
		{[]string{"secret"}, "Work with the one local vault"},
		{[]string{"secret", "add"}, "Add one or more secrets"},
		{[]string{"secret", "update"}, "Replace the value"},
		{[]string{"secret", "delete"}, "Delete one or more secrets"},
		{[]string{"secret", "get"}, "Retrieve a secret value"},
		{[]string{"secret", "retrieve"}, "Retrieve a secret value"},
		{[]string{"secret", "list"}, "List vault items"},
		{[]string{"secret", "expose"}, "Expose one vault item"},
		{[]string{"secret", "hide"}, "Remove one repo exposure"},
		{[]string{"app"}, "Connect a normal application"},
		{[]string{"app", "connect"}, "Save an app profile"},
		{[]string{"app", "run"}, "Run the saved app command"},
		{[]string{"app", "install"}, "Create or refresh the managed launcher"},
		{[]string{"app", "shell"}, "Open a login shell"},
		{[]string{"app", "disconnect"}, "Remove the saved app profile"},
		{[]string{"app", "list"}, "List saved apps"},
		{[]string{"agent"}, "Connect a coding agent"},
		{[]string{"agent", "connect"}, "Write the local agent config"},
		{[]string{"agent", "mcp"}, "Run the agent-specific HASP MCP wrapper"},
		{[]string{"agent", "launch"}, "Run a command under an agent-safe HASP session"},
		{[]string{"agent", "shell"}, "Open a shell under an agent-safe HASP session"},
		{[]string{"agent", "disconnect"}, "Remove the HASP config block"},
		{[]string{"agent", "list"}, "List saved agents"},
		{[]string{"project"}, "Manage repo boundaries"},
		{[]string{"run"}, "Run one repo-scoped command"},
		{[]string{"inject"}, "Resolve repo-scoped refs"},
		{[]string{"write-env"}, "Write a convenience env file"},
		{[]string{"check-repo"}, "Scan a repo"},
		{[]string{"daemon"}, "Manage the local runtime daemon"},
		{[]string{"session"}, "Work with broker sessions"},
		{[]string{"session", "grant-plaintext"}, "Grant one-time plaintext reveal/copy"},
		{[]string{"session", "grant-mutation"}, "Grant one-time secret delete/expose/hide"},
		{[]string{"status"}, "Show local daemon and vault status"},
		{[]string{"ping"}, "Check whether the local daemon"},
		{[]string{"audit"}, "Print the local audit log"},
		{[]string{"export-backup"}, "Write an encrypted backup"},
		{[]string{"restore-backup"}, "Restore an encrypted backup"},
		{[]string{"mcp"}, "Start the MCP server"},
		{[]string{"tui"}, "Deprecated"},
		{[]string{"version"}, "Print the build version"},
	}

	for _, topic := range topics {
		var out bytes.Buffer
		if err := printHelpTopic(&out, topic.args); err != nil {
			t.Fatalf("printHelpTopic(%v): %v", topic.args, err)
		}
		if !strings.Contains(out.String(), topic.mustSee) {
			t.Fatalf("help topic %v missing %q in %q", topic.args, topic.mustSee, out.String())
		}
	}
}

func TestRootCommandInventoryStaysInSyncWithHelp(t *testing.T) {
	rootHelp := renderRootHelpText()
	dailySection := rootHelp
	if start := strings.Index(rootHelp, "Daily commands"); start >= 0 {
		dailySection = rootHelp[start:]
	}
	if end := strings.Index(dailySection, "Help topics"); end >= 0 {
		dailySection = dailySection[:end]
	}
	for _, spec := range rootCommandInventory() {
		if spec.group != commandGroupDaily && spec.group != commandGroupUtility {
			t.Fatalf("unexpected command group for %s: %s", spec.name, spec.group)
		}
		commandRow := fmt.Sprintf("  %-17s", spec.name)
		if spec.group == commandGroupDaily && !spec.hidden && !strings.Contains(dailySection, commandRow) {
			t.Fatalf("root help missing daily command %q", spec.name)
		}
		if spec.group == commandGroupUtility && !spec.hidden && strings.Contains(dailySection, commandRow) {
			t.Fatalf("root help should not promote utility command %q; use explicit help/completion instead", spec.name)
		}
		if len(spec.helpTopic) == 0 {
			continue
		}
		key := strings.Join(spec.helpTopic, " ")
		if _, ok := helpTopicByKey[key]; !ok {
			t.Fatalf("inventory command %q references missing help topic %q", spec.name, key)
		}
	}
}

func TestRunWithStarterHelpRoutes(t *testing.T) {
	starter := &fakeStarter{}
	cases := []struct {
		args    []string
		mustSee string
	}{
		{[]string{"help", "version"}, "Print the build version"},
		{[]string{"setup", "--help"}, "Guide a user through machine setup"},
		{[]string{"bootstrap", "--help"}, "Configure a repo and an agent profile"},
		{[]string{"import", "--help"}, "Import secrets from a .env file"},
		{[]string{"set", "--help"}, "Add or replace one secret"},
		{[]string{"capture", "--help"}, "Save a value into the vault"},
		{[]string{"audit", "--help"}, "Print the local audit log"},
		{[]string{"ping", "--help"}, "Check whether the local daemon"},
		{[]string{"status", "--help"}, "Show local daemon and vault status"},
		{[]string{"run", "--help"}, "Run one repo-scoped command"},
		{[]string{"inject", "--help"}, "Resolve repo-scoped refs"},
		{[]string{"write-env", "--help"}, "Write a convenience env file"},
		{[]string{"check-repo", "--help"}, "Scan a repo"},
		{[]string{"export-backup", "--help"}, "Write an encrypted backup"},
		{[]string{"restore-backup", "--help"}, "Restore an encrypted backup"},
		{[]string{"mcp", "--help"}, "Start the MCP server"},
		{[]string{"tui", "--help"}, "Deprecated"},
	}

	for _, tc := range cases {
		var out bytes.Buffer
		if err := runWithStarter(context.Background(), tc.args, bytes.NewBuffer(nil), &out, io.Discard, starter); err != nil {
			t.Fatalf("runWithStarter(%v): %v", tc.args, err)
		}
		if !strings.Contains(out.String(), tc.mustSee) {
			t.Fatalf("runWithStarter(%v) missing %q in %q", tc.args, tc.mustSee, out.String())
		}
	}
}

func TestCompositeCommandsHelpBranches(t *testing.T) {
	starter := &fakeStarter{}

	var appOut bytes.Buffer
	if err := appConsumerCommand(context.Background(), []string{"connect", "--help"}, bytes.NewBuffer(nil), &appOut, io.Discard, starter); err != nil {
		t.Fatalf("app connect help: %v", err)
	}
	if !strings.Contains(appOut.String(), "Launcher creation is never silent") {
		t.Fatalf("unexpected app connect help: %q", appOut.String())
	}

	var agentOut bytes.Buffer
	if err := agentConsumerCommand(context.Background(), []string{"connect", "--help"}, bytes.NewBuffer(nil), &agentOut, io.Discard); err != nil {
		t.Fatalf("agent connect help: %v", err)
	}
	if !strings.Contains(agentOut.String(), "Write the local agent config") {
		t.Fatalf("unexpected agent connect help: %q", agentOut.String())
	}

	agentOut.Reset()
	if err := agentConsumerCommand(context.Background(), []string{"shell", "--help"}, bytes.NewBuffer(nil), &agentOut, io.Discard); err != nil {
		t.Fatalf("agent shell help: %v", err)
	}
	if !strings.Contains(agentOut.String(), "Open a shell under an agent-safe HASP session") {
		t.Fatalf("unexpected agent shell help: %q", agentOut.String())
	}

	var secretOut bytes.Buffer
	if err := secretCommand(context.Background(), []string{"add", "--help"}, bytes.NewBuffer(nil), &secretOut, io.Discard); err != nil {
		t.Fatalf("secret add help: %v", err)
	}
	if !strings.Contains(secretOut.String(), "Add one or more secrets") {
		t.Fatalf("unexpected secret add help: %q", secretOut.String())
	}
}
