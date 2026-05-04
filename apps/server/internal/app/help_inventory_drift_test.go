package app

import (
	"bytes"
	"strings"
	"testing"
)

// TestHelpParentTopicsCoverEverySubcommand walks helpTopicInventory and
// asserts that every multi-word ("secret get", "app run", …) help topic's
// last word appears in its parent topic's "Subcommands" section. This is
// the drift trap from the punch list: when a new subcommand is registered
// (e.g. "secret rotate", "agent list-supported"), the parent's hand-edited
// "Subcommands" section is the easiest place to forget to update.
//
// Audit-event schema and internal type names are not in scope; this only
// inspects the user-facing help body.
func TestHelpParentTopicsCoverEverySubcommand(t *testing.T) {
	lockAppSeams(t)

	parents := make(map[string][]string)
	for _, spec := range helpTopicInventory {
		parts := strings.Fields(spec.key)
		if len(parts) < 2 {
			continue
		}
		parent := strings.Join(parts[:len(parts)-1], " ")
		sub := parts[len(parts)-1]
		parents[parent] = append(parents[parent], sub)
	}

	for parent, subs := range parents {
		text, ok := helpTopicByKey[parent]
		if !ok {
			t.Errorf("inventory has subcommand under %q but no parent help topic", parent)
			continue
		}
		section := extractSubcommandsSection(text)
		if section == "" {
			t.Errorf("help topic %q has subcommands but no `Subcommands` section:\n%s", parent, text)
			continue
		}
		for _, sub := range subs {
			if !subcommandsSectionListsEntry(section, sub) {
				t.Errorf("help topic %q `Subcommands` section omits %q:\n%s", parent, sub, section)
			}
		}
	}
}

// extractSubcommandsSection returns the body of the "Subcommands" section
// (the lines after the heading until the next blank-line-separated section)
// or "" when the help text does not have one.
func extractSubcommandsSection(text string) string {
	lines := strings.Split(text, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "Subcommands" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return ""
	}
	end := len(lines)
	for i := start; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			end = i
			break
		}
		// A new heading (no leading indent + non-empty) ends the section.
		if !strings.HasPrefix(lines[i], " ") && trimmed != "" && i > start {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// subcommandsSectionListsEntry returns true when sub appears as the first
// non-whitespace token of any line in the Subcommands body.
func subcommandsSectionListsEntry(section, sub string) bool {
	for _, line := range strings.Split(section, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == sub {
			return true
		}
	}
	return false
}

// TestHelpTopicInventoryHasNoOrphans guards the inverse direction: every
// subcommand topic key has a corresponding parent topic the user can
// navigate up to (via `hasp help <parent>`). Without this, a typo like
// "secrets get" would silently ship as a dangling page.
func TestHelpTopicInventoryHasNoOrphans(t *testing.T) {
	lockAppSeams(t)

	keys := make(map[string]struct{}, len(helpTopicInventory))
	for _, spec := range helpTopicInventory {
		keys[spec.key] = struct{}{}
	}
	for _, spec := range helpTopicInventory {
		parts := strings.Fields(spec.key)
		if len(parts) < 2 {
			continue
		}
		parent := strings.Join(parts[:len(parts)-1], " ")
		if _, ok := keys[parent]; !ok {
			t.Errorf("subcommand topic %q has no parent topic %q registered", spec.key, parent)
		}
	}
}

// TestBootstrapHelpListsKnownSubforms guards the specific drift the
// adversarial review caught: `hasp bootstrap` help advertised the bare
// form but skipped `bootstrap generic` and `bootstrap doctor`, both of
// which the dispatcher accepts. Their presence in examples is not enough
// — they should appear as discoverable Subcommands entries.
func TestBootstrapHelpListsKnownSubforms(t *testing.T) {
	lockAppSeams(t)

	var buf bytes.Buffer
	if err := printHelpTopic(&buf, []string{"bootstrap"}); err != nil {
		t.Fatalf("printHelpTopic bootstrap: %v", err)
	}
	section := extractSubcommandsSection(buf.String())
	if section == "" {
		t.Fatalf("bootstrap help has no Subcommands section:\n%s", buf.String())
	}
	for _, want := range []string{"generic", "doctor"} {
		if !subcommandsSectionListsEntry(section, want) {
			t.Errorf("bootstrap help Subcommands section omits %q:\n%s", want, buf.String())
		}
	}
}

// TestSecretHelpListsRetrieveAlias guards the published `secret retrieve`
// alias: it is registered in helpTopicInventory and accepted by the
// dispatcher, so the parent `hasp secret` page should list it as a real
// Subcommands entry, not just mention the word in passing.
func TestSecretHelpListsRetrieveAlias(t *testing.T) {
	lockAppSeams(t)

	var buf bytes.Buffer
	if err := printHelpTopic(&buf, []string{"secret"}); err != nil {
		t.Fatalf("printHelpTopic secret: %v", err)
	}
	section := extractSubcommandsSection(buf.String())
	if !subcommandsSectionListsEntry(section, "retrieve") {
		t.Errorf("`hasp secret` Subcommands section omits `retrieve` alias:\n%s", buf.String())
	}
}
