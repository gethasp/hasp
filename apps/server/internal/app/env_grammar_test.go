package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// hasp-l91g: --env NAME=@REF is the canonical grammar across run, write-env,
// and app connect. Bare NAME=REF still resolves during the deprecation window
// but must emit a stderr warning pointing at the @-prefixed form.

func TestWarnBareEnvRefsEmitsDeprecationForUnprefixedReferences(t *testing.T) {
	var stderr bytes.Buffer
	mapping := mappingFlag{
		"OPENAI_API_KEY": "OPENAI_API_KEY",
		"DATABASE_URL":   "@DATABASE_URL",
	}
	warnBareEnvRefs(context.Background(), &stderr, mapping, "run", "--env")
	got := stderr.String()
	if !strings.Contains(got, "deprecated") {
		t.Fatalf("expected deprecation in stderr, got %q", got)
	}
	if !strings.Contains(got, "OPENAI_API_KEY") {
		t.Fatalf("expected stderr to mention the bare key OPENAI_API_KEY, got %q", got)
	}
	if strings.Contains(got, "DATABASE_URL") {
		t.Fatalf("@-prefixed key DATABASE_URL must not be flagged, got %q", got)
	}
	if !strings.Contains(got, "@") {
		t.Fatalf("expected stderr to point at @-prefixed form, got %q", got)
	}
}

func TestWarnBareEnvRefsSilentWhenAllPrefixed(t *testing.T) {
	var stderr bytes.Buffer
	mapping := mappingFlag{"DATABASE_URL": "@DATABASE_URL", "OPENAI_API_KEY": "@OPENAI_API_KEY"}
	warnBareEnvRefs(context.Background(), &stderr, mapping, "run", "--env")
	if stderr.Len() != 0 {
		t.Fatalf("expected silence when all refs are @-prefixed, got %q", stderr.String())
	}
}

func TestWarnBareEnvRefsNoopWithNilStderr(t *testing.T) {
	mapping := mappingFlag{"OPENAI_API_KEY": "OPENAI_API_KEY"}
	warnBareEnvRefs(context.Background(), nil, mapping, "run", "--env")
}

func TestWarnBareEnvRefsSilentWhenEmpty(t *testing.T) {
	var stderr bytes.Buffer
	warnBareEnvRefs(context.Background(), &stderr, mappingFlag{}, "run", "--env")
	if stderr.Len() != 0 {
		t.Fatalf("expected silence on empty mapping, got %q", stderr.String())
	}
}

// TestRunCommandStderrWarnsOnBareEnvRef exercises the dispatcher path: a
// `hasp run --env FOO=BAR -- ...` invocation must surface a deprecation
// warning on stderr even when the broker call later fails for unrelated
// reasons (no project binding, unknown ref, etc.).
func TestRunCommandStderrWarnsOnBareEnvRef(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	var stderr bytes.Buffer
	// We don't care about success here; only that the bare-env warning
	// fires before the broker work begins.
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	_ = runWithStarter(context.Background(),
		[]string{"run", "--project-root", t.TempDir(), "--env", "FOO=BAR_BARE", "--", "true"},
		bytes.NewBuffer(nil), bytes.NewBuffer(nil), &stderr,
		newDaemonTestStarter(t),
	)
	got := stderr.String()
	if !strings.Contains(got, "deprecated") || !strings.Contains(got, "FOO") || !strings.Contains(got, "@") {
		t.Fatalf("expected deprecation warning naming FOO and pointing at @REF, got %q", got)
	}
}

func TestWarnBareEnvRefsNamesCommandAndFlag(t *testing.T) {
	var stderr bytes.Buffer
	warnBareEnvRefs(context.Background(), &stderr, mappingFlag{"FOO": "BAR"}, "app connect", "--dotenv")
	got := stderr.String()
	if !strings.Contains(got, "app connect") {
		t.Fatalf("expected stderr to mention 'app connect', got %q", got)
	}
	if !strings.Contains(got, "--dotenv") {
		t.Fatalf("expected stderr to mention '--dotenv', got %q", got)
	}
}
