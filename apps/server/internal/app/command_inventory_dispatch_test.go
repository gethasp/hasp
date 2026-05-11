package app

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
)

// hasp-wlkm: bootstrap and redact were previously hardcoded in
// runWithStarter's switch, which forked the dispatch contract from every
// other root command. These tests pin three things now that they live in
// the inventory: bootstrap still routes its --help to the bootstrap topic
// without invoking the handler, redact still dispatches to its handler
// (and is correctly hidden from the user-facing help listing), and the
// inventory is memoized so repeated calls share the same backing array
// instead of rebuilding the closure list per dispatch.

func TestRootCommandInventoryReturnsSameBackingArray(t *testing.T) {
	a := rootCommandInventory()
	b := rootCommandInventory()
	if len(a) == 0 {
		t.Fatal("inventory must not be empty")
	}
	if len(a) != len(b) {
		t.Fatalf("inventory length changed across calls: %d vs %d", len(a), len(b))
	}
	if &a[0] != &b[0] {
		t.Fatal("rootCommandInventory must memoize: repeated calls should return the same backing array")
	}
}

func TestCompletionSubcommandsComeFromInventory(t *testing.T) {
	got := subcommandMap()
	for _, spec := range rootCommandInventory() {
		if len(spec.subcommands) == 0 {
			continue
		}
		subs, ok := got[spec.name]
		if !ok {
			t.Fatalf("completion map missing inventory subcommands for %q", spec.name)
		}
		for _, sub := range spec.subcommands {
			if !slices.Contains(subs, sub) {
				t.Fatalf("completion map for %q missing %q from inventory: %v", spec.name, sub, subs)
			}
		}
	}
}

func TestBootstrapHelpDispatchesViaInventory(t *testing.T) {
	starter := &fakeStarter{}
	var stdout bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"bootstrap", "--help"}, bytes.NewBuffer(nil), &stdout, &bytes.Buffer{}, starter); err != nil {
		t.Fatalf("runWithStarter bootstrap --help: %v", err)
	}
	if !strings.Contains(stdout.String(), "Configure a repo and an agent profile") {
		t.Fatalf("expected bootstrap help text, got %q", stdout.String())
	}

	spec, ok := lookupRootCommand("bootstrap")
	if !ok {
		t.Fatal("bootstrap must be in the root command inventory")
	}
	if len(spec.helpTopic) == 0 || spec.helpTopic[0] != "bootstrap" {
		t.Fatalf("bootstrap inventory entry must declare helpTopic=[\"bootstrap\"]; got %v", spec.helpTopic)
	}
}

func TestRedactIsRegisteredButHiddenFromRootHelp(t *testing.T) {
	spec, ok := lookupRootCommand("redact")
	if !ok {
		t.Fatal("redact must be in the root command inventory")
	}
	if !spec.hidden {
		t.Fatal("redact must be marked hidden so it does not appear in the user-facing help")
	}

	rootHelp := renderRootHelpText()
	for _, line := range strings.Split(rootHelp, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "redact ") {
			t.Fatalf("hidden command redact must not appear in root help; saw line %q", line)
		}
	}
}
