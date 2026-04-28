package app

// RED tests for hasp-jy2: refuse argv-delivered plaintext in secret add / set.
//
// Expected warning string (GREEN must emit this to stderr on every --value call):
//   "WARNING: --value puts the secret on argv (visible in ps, shell history); prefer --value-stdin"
//
// Expected error string (GREEN must return for NAME=VALUE positional arg):
//   "refusing secret value on argv: use interactive prompt, --from-stdin, or --from-file (value visible in ps/history)"

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// bootstrapVaultForArgvTest creates a temp HASP_HOME, sets HASP_MASTER_PASSWORD,
// runs hasp init, and returns the context to use.
func bootstrapVaultForArgvTest(t *testing.T) context.Context {
	t.Helper()
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	ctx := context.Background()
	if err := Run(ctx, []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	return ctx
}

// TestSecretAddRefusesNameValueOnArgv verifies that NAME=VALUE positional args
// are rejected with a clear error mentioning argv exposure.
func TestSecretAddRefusesNameValueOnArgv(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	err := secretAddCommand(ctx, []string{"API_TOKEN=abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error for NAME=VALUE positional arg, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "argv") && !strings.Contains(msg, "ps") && !strings.Contains(msg, "history") {
		t.Fatalf("expected error to mention argv/ps/history exposure, got: %q", msg)
	}

	// Verify the secret was NOT stored.
	var getOut bytes.Buffer
	getErr := secretGetCommand(ctx, []string{"API_TOKEN"}, bytes.NewBuffer(nil), &getOut, io.Discard)
	if getErr == nil {
		t.Fatalf("expected API_TOKEN to not exist after rejected add, but secretGetCommand succeeded: %s", getOut.String())
	}
}

// TestSecretAddAcceptsBarePositionalAndPromptsForValue verifies that a bare
// positional NAME arg (no =) triggers the interactive prompt and stores the secret.
func TestSecretAddAcceptsBarePositionalAndPromptsForValue(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	// Stdin: value line + newline, then "n" to answer "Add another? [Y/n]"
	stdin := bytes.NewBufferString("supersecret\nn\n")
	err := secretAddCommand(ctx, []string{"--vault-only", "MY_KEY"}, stdin, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("secretAddCommand with bare name: %v", err)
	}

	// Verify the secret was stored.
	var getOut bytes.Buffer
	if err := secretGetCommand(ctx, []string{"MY_KEY", "--reveal"}, bytes.NewBuffer(nil), &getOut, io.Discard); err != nil {
		t.Fatalf("secretGetCommand MY_KEY: %v", err)
	}
	if !strings.Contains(getOut.String(), "supersecret") {
		t.Fatalf("expected stored value 'supersecret', got: %q", getOut.String())
	}
}

// TestSetEmitsWarningOnValueFlag verifies that --value still succeeds but emits
// a warning to stderr about argv exposure.
func TestSetEmitsWarningOnValueFlag(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	var stderrBuf bytes.Buffer
	err := setCommand(ctx, []string{"--name", "X", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, &stderrBuf)
	if err != nil {
		t.Fatalf("setCommand with --value must not fail, got: %v", err)
	}
	warn := stderrBuf.String()
	if !strings.Contains(warn, "argv") && !strings.Contains(warn, "visible in ps") && !strings.Contains(warn, "plaintext") {
		t.Fatalf("expected stderr warning about argv exposure, got: %q", warn)
	}
}

// TestSetValueStdinReadsValueWithoutArgvExposure verifies that --value-stdin
// reads from stdin, stores the secret, and does NOT emit the argv warning.
func TestSetValueStdinReadsValueWithoutArgvExposure(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	stdin := bytes.NewBufferString("abc123\n")
	var stderrBuf bytes.Buffer
	err := setCommand(ctx, []string{"--name", "X", "--value-stdin"}, stdin, io.Discard, &stderrBuf)
	if err != nil {
		t.Fatalf("setCommand with --value-stdin: %v", err)
	}

	// No warning on stderr for the safe path.
	warn := stderrBuf.String()
	if strings.Contains(warn, "argv") || strings.Contains(warn, "visible in ps") || strings.Contains(warn, "plaintext") {
		t.Fatalf("expected no argv warning for --value-stdin, got: %q", warn)
	}

	// Secret must be stored with the correct value.
	var getOut bytes.Buffer
	if err := secretGetCommand(ctx, []string{"X", "--reveal"}, bytes.NewBuffer(nil), &getOut, io.Discard); err != nil {
		t.Fatalf("secretGetCommand X: %v", err)
	}
	if !strings.Contains(getOut.String(), "abc123") {
		t.Fatalf("expected stored value 'abc123', got: %q", getOut.String())
	}
}

// TestSetValueAndValueStdinAreMutuallyExclusive verifies that passing both
// --value and --value-stdin is a usage error.
func TestSetValueAndValueStdinAreMutuallyExclusive(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	err := setCommand(ctx, []string{"--name", "X", "--value", "foo", "--value-stdin"}, bytes.NewBufferString("bar\n"), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error when both --value and --value-stdin are supplied")
	}
}

// TestSetValueStdinEmptyInputFails verifies that --value-stdin with an empty
// stdin returns an error mentioning "empty value".
func TestSetValueStdinEmptyInputFails(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	err := setCommand(ctx, []string{"--name", "X", "--value-stdin"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error for empty --value-stdin input")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected 'empty' in error, got: %q", err.Error())
	}
}

// TestSecretAddFromStdinSingleName verifies that --from-stdin with a single bare
// positional NAME arg reads the value from stdin and stores the secret.
func TestSecretAddFromStdinSingleName(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	stdin := bytes.NewBufferString("abc123\n")
	err := secretAddCommand(ctx, []string{"--from-stdin", "--vault-only", "API_TOKEN"}, stdin, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("secretAddCommand --from-stdin: %v", err)
	}

	var getOut bytes.Buffer
	if err := secretGetCommand(ctx, []string{"API_TOKEN", "--reveal"}, bytes.NewBuffer(nil), &getOut, io.Discard); err != nil {
		t.Fatalf("secretGetCommand API_TOKEN: %v", err)
	}
	if !strings.Contains(getOut.String(), "abc123") {
		t.Fatalf("expected stored value 'abc123', got: %q", getOut.String())
	}
}

// TestSecretAddFromStdinRejectsMultipleNames verifies that --from-stdin with
// more than one positional NAME arg is a usage error (ambiguous assignment).
func TestSecretAddFromStdinRejectsMultipleNames(t *testing.T) {
	lockAppSeams(t)
	ctx := bootstrapVaultForArgvTest(t)

	err := secretAddCommand(ctx, []string{"--from-stdin", "A", "B"}, bytes.NewBufferString("value\n"), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error when --from-stdin is paired with multiple positional names")
	}
}
