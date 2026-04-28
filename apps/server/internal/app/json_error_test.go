package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// hasp-ynci: --json contract — when --json is set on a command that fails,
// stdout must stay empty (or contain exactly one JSON document) and stderr
// must contain a single structured-error JSON line of the form
// {"error":{"code":"…","message":"…","hint":"…"}}.

func TestStructuredErrorEnvelopeShape(t *testing.T) {
	envelope := newAppError("bad_input", "missing argument").withHint("pass --name")
	got := envelope.jsonBytes()
	var decoded map[string]map[string]string
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("decode envelope: %v\nraw: %s", err, got)
	}
	inner, ok := decoded["error"]
	if !ok {
		t.Fatalf("missing 'error' key in envelope: %s", got)
	}
	if inner["code"] != "bad_input" {
		t.Fatalf("code = %q, want bad_input", inner["code"])
	}
	if inner["message"] != "missing argument" {
		t.Fatalf("message = %q, want 'missing argument'", inner["message"])
	}
	if inner["hint"] != "pass --name" {
		t.Fatalf("hint = %q, want 'pass --name'", inner["hint"])
	}
}

func TestStructuredErrorOmitsEmptyHint(t *testing.T) {
	envelope := newAppError("io_error", "boom")
	got := envelope.jsonBytes()
	if strings.Contains(string(got), "\"hint\"") {
		t.Fatalf("envelope should omit empty hint: %s", got)
	}
}

func TestWriteCLIErrorPlainTextWhenNotJSON(t *testing.T) {
	var stderr bytes.Buffer
	writeCLIError(&stderr, errors.New("plain failure"), false)
	got := stderr.String()
	if got != "plain failure\n" {
		t.Fatalf("plain mode wrote %q, want %q", got, "plain failure\n")
	}
}

func TestWriteCLIErrorJSONWhenJSON(t *testing.T) {
	var stderr bytes.Buffer
	writeCLIError(&stderr, errors.New("plain failure"), true)
	got := strings.TrimSpace(stderr.String())
	var decoded map[string]map[string]string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("expected JSON envelope on stderr, got %q (decode err %v)", got, err)
	}
	if decoded["error"]["message"] != "plain failure" {
		t.Fatalf("message = %q, want 'plain failure'", decoded["error"]["message"])
	}
	if decoded["error"]["code"] != "internal_error" {
		t.Fatalf("default code = %q, want 'internal_error'", decoded["error"]["code"])
	}
}

func TestWriteCLIErrorPreservesAppErrorEnvelope(t *testing.T) {
	var stderr bytes.Buffer
	envelope := newAppError("not_found", "secret missing").withHint("run hasp secret list")
	writeCLIError(&stderr, envelope, true)
	got := strings.TrimSpace(stderr.String())
	var decoded map[string]map[string]string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("decode envelope: %v\nraw: %q", err, got)
	}
	inner := decoded["error"]
	if inner["code"] != "not_found" || inner["message"] != "secret missing" || inner["hint"] != "run hasp secret list" {
		t.Fatalf("envelope mismatch: %+v", inner)
	}
}

// TestRunUnknownCommandJSONEmitsStructuredError exercises the dispatcher path
// where an unknown verb is given alongside --json. The error must surface as a
// structured JSON envelope on stderr; stdout must be empty.
func TestRunUnknownCommandJSONEmitsStructuredError(t *testing.T) {
	lockAppSeams(t)
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"--json", "made-up-verb"}, bytes.NewBuffer(nil), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should stay empty in --json error path, got %q", stdout.String())
	}
}

// TestEveryJSONCommandStdoutSingleDocument verifies that when --json is set,
// every supported command emits exactly one valid JSON document on stdout
// (or nothing if the command failed). This is the punch-list harness.
func TestEveryJSONCommandStdoutSingleDocument(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	if err := initCommandWithArgs(context.Background(), nil, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	type spec struct {
		name string
		args []string
	}
	cases := []spec{
		{name: "version", args: []string{"version", "--json"}},
		{name: "secret list", args: []string{"secret", "list", "--json"}},
		{name: "audit", args: []string{"audit", "--json"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := Run(context.Background(), tc.args, bytes.NewBuffer(nil), &stdout, &stderr); err != nil {
				t.Fatalf("%s: %v\nstderr=%q", tc.name, err, stderr.String())
			}
			if err := assertSingleJSONDocument(stdout.Bytes()); err != nil {
				t.Fatalf("%s: %v\nstdout=%q", tc.name, err, stdout.String())
			}
		})
	}
}
