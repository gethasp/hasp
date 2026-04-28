package app

// RED tests for hasp-q3go — collapse user-facing taxonomy to 4 concepts.
// Contract pinned:
//
//   - Root help prelude advertises exactly these 4 surface nouns: vault,
//     repo, agent, grant. (App is folded into agent for first-time users —
//     "agent" covers both reusable app profiles and one-off coding agents.)
//   - Lower-level terms (consumer, binding, exposure, reference, alias,
//     named_reference, lease, scope, session token, broker) do not appear in
//     the root prelude or in the daily-command summaries.
//   - `hasp help internals` is registered and surfaces the lower-level
//     vocabulary for operators who need it.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestRootHelpPreludeShowsFourConcepts(t *testing.T) {
	lockAppSeams(t)
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"help"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("help: %v", err)
	}
	out := stdout.String()
	// Cut the prelude — Core concepts ends at the first command section.
	prelude := out
	if idx := strings.Index(out, "Daily commands"); idx >= 0 {
		prelude = out[:idx]
	}
	for _, want := range []string{"vault", "repo", "agent", "grant"} {
		if !strings.Contains(prelude, want) {
			t.Fatalf("expected prelude to mention %q, got:\n%s", want, prelude)
		}
	}
}

func TestRootHelpPreludeOmitsLowLevelTerms(t *testing.T) {
	lockAppSeams(t)
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"help"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("help: %v", err)
	}
	out := stdout.String()
	prelude := out
	if idx := strings.Index(out, "Daily commands"); idx >= 0 {
		prelude = out[:idx]
	}
	// Each of these is a leaked plumbing term that scares first-time users.
	// They belong in `hasp help internals`, not on page one.
	forbidden := []string{
		"consumer",
		"named_reference",
		"named reference",
		"binding",
		"exposure",
		"lease",
		"session token",
	}
	for _, term := range forbidden {
		if strings.Contains(strings.ToLower(prelude), term) {
			t.Fatalf("root prelude leaks low-level term %q:\n%s", term, prelude)
		}
	}
}

func TestHelpInternalsTopicIsRegistered(t *testing.T) {
	lockAppSeams(t)
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"help", "internals"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("help internals: %v", err)
	}
	out := strings.ToLower(stdout.String())
	for _, term := range []string{"consumer", "lease", "scope", "binding"} {
		if !strings.Contains(out, term) {
			t.Fatalf("expected `help internals` to surface %q, got:\n%s", term, out)
		}
	}
}

func TestRootHelpListsInternalsTopic(t *testing.T) {
	lockAppSeams(t)
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"help"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(stdout.String(), "hasp help internals") {
		t.Fatalf("expected root help to list 'hasp help internals' topic, got:\n%s", stdout.String())
	}
}
