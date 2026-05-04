package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// hasp-yxsx: Operators editing .env files have no safe way to confirm a
// candidate file matches the vault. `secret diff <path>` buckets each name
// into {same, changed, missing, extra} — comparing values internally but
// never emitting them.

func TestSecretDiffCommandBucketsByPresenceAndValue(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, pair := range []struct{ name, value string }{
		{"AAA", "foo"},
		{"BBB", "bar"},
		{"CCC", "baz"},
	} {
		if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--vault-only", pair.name}, bytes.NewBufferString(pair.value), io.Discard, io.Discard); err != nil {
			t.Fatalf("secret add %s: %v", pair.name, err)
		}
	}

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("AAA=foo\nBBB=changed\nDDD=extra\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	var out bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "diff", "--json", envPath}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("secret diff: %v", err)
	}

	var payload struct {
		Same    []string `json:"same"`
		Changed []string `json:"changed"`
		Missing []string `json:"missing"`
		Extra   []string `json:"extra"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("decode diff output: %v: %s", err, out.String())
	}
	sort.Strings(payload.Same)
	sort.Strings(payload.Changed)
	sort.Strings(payload.Missing)
	sort.Strings(payload.Extra)

	if !reflect.DeepEqual(payload.Same, []string{"AAA"}) {
		t.Fatalf("expected same=[AAA], got %v", payload.Same)
	}
	if !reflect.DeepEqual(payload.Changed, []string{"BBB"}) {
		t.Fatalf("expected changed=[BBB], got %v", payload.Changed)
	}
	if !reflect.DeepEqual(payload.Missing, []string{"CCC"}) {
		t.Fatalf("expected missing=[CCC], got %v", payload.Missing)
	}
	if !reflect.DeepEqual(payload.Extra, []string{"DDD"}) {
		t.Fatalf("expected extra=[DDD], got %v", payload.Extra)
	}
}

func TestSecretDiffCommandNeverEmitsValues(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	const vaultValue = "vault-only-secret-marker"
	if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--vault-only", "TOKEN"}, bytes.NewBufferString(vaultValue), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}

	envPath := filepath.Join(t.TempDir(), ".env")
	const envValue = "candidate-env-value-marker"
	if err := os.WriteFile(envPath, []byte("TOKEN="+envValue+"\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	for _, mode := range [][]string{{"--json"}, nil} {
		args := []string{"secret", "diff"}
		args = append(args, mode...)
		args = append(args, envPath)
		var out bytes.Buffer
		if err := Run(context.Background(), args, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
			t.Fatalf("secret diff %v: %v", args, err)
		}
		body := out.String()
		if strings.Contains(body, vaultValue) {
			t.Fatalf("vault value leaked into diff output (args=%v): %q", args, body)
		}
		if strings.Contains(body, envValue) {
			t.Fatalf("env value leaked into diff output (args=%v): %q", args, body)
		}
	}
}

func TestSecretDiffCommandRequiresPath(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "diff"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected missing path argument to fail")
	}
}

func TestSecretDiffCommandHumanRendersBucketCounts(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := Run(context.Background(), []string{"secret", "add", "--from-stdin", "--vault-only", "PRESENT"}, bytes.NewBufferString("v1"), io.Discard, io.Discard); err != nil {
		t.Fatalf("secret add: %v", err)
	}

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("PRESENT=v1\nEXTRA=other\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	var out bytes.Buffer
	if err := Run(context.Background(), []string{"secret", "diff", envPath}, bytes.NewBuffer(nil), &out, io.Discard); err != nil {
		t.Fatalf("secret diff: %v", err)
	}
	body := out.String()
	for _, want := range []string{"same", "PRESENT", "extra", "EXTRA"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected human output to contain %q, got %q", want, body)
		}
	}
}
