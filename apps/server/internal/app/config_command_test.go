package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

func TestConfigShowGetSetCommandsUseDaemonConfig(t *testing.T) {
	lockAppSeams(t)
	t.Setenv("HASP_HOME", t.TempDir())
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)
	if err := runWithStarter(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err != nil {
		t.Fatalf("init: %v", err)
	}
	var showOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"config", "show", "--json"}, bytes.NewBuffer(nil), &showOut, io.Discard, starter); err != nil {
		t.Fatalf("config show --json: %v", err)
	}
	var show runtime.ConfigResponse
	if err := json.Unmarshal(showOut.Bytes(), &show); err != nil {
		t.Fatalf("decode config show: %v\n%s", err, showOut.String())
	}
	if show.Config["audit.retention_days"] == nil || show.Config["hmac.secret"] != nil || bytes.Contains(showOut.Bytes(), []byte("master_password")) {
		t.Fatalf("config show leaked or omitted wrong keys: %s", showOut.String())
	}
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("connect daemon: %v", err)
	}
	rpcReply, err := client.Config(context.Background())
	if err != nil {
		t.Fatalf("runtime config: %v", err)
	}
	_ = client.Close()
	rpcJSON, err := json.Marshal(rpcReply)
	if err != nil {
		t.Fatalf("marshal rpc config: %v", err)
	}
	if !bytes.Equal(normalizeJSONBytes(t, showOut.Bytes()), normalizeJSONBytes(t, rpcJSON)) {
		t.Fatalf("cli/runtime config mismatch\ncli=%s\nrpc=%s", showOut.String(), rpcJSON)
	}
	if err := runWithStarter(context.Background(), []string{"config", "set", "audit.retention_days", "120"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err != nil {
		t.Fatalf("config set: %v", err)
	}
	var getOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"config", "get", "audit.retention_days"}, bytes.NewBuffer(nil), &getOut, io.Discard, starter); err != nil {
		t.Fatalf("config get: %v", err)
	}
	if strings.TrimSpace(getOut.String()) != "120" {
		t.Fatalf("config get output = %q, want 120", getOut.String())
	}
	if err := runWithStarter(context.Background(), []string{"config", "get", "hmac.secret"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err == nil || !strings.Contains(err.Error(), "config key not found") {
		t.Fatalf("config get hmac.secret err = %v, want not found", err)
	}
	if err := runWithStarter(context.Background(), []string{"config", "set", "hmac.secret", "do-not-expose"}, bytes.NewBuffer(nil), io.Discard, io.Discard, starter); err == nil || !strings.Contains(err.Error(), "config key not found") || strings.Contains(err.Error(), "do-not-expose") {
		t.Fatalf("config set hmac.secret err = %v, want not found without value", err)
	}
}

func TestConfigHelpAndCompletionAreWired(t *testing.T) {
	lockAppSeams(t)
	var help bytes.Buffer
	if err := Run(context.Background(), []string{"help", "config"}, bytes.NewBuffer(nil), &help, io.Discard); err != nil {
		t.Fatalf("hasp help config: %v", err)
	}
	if !strings.Contains(help.String(), "show") || !strings.Contains(help.String(), "get") || !strings.Contains(help.String(), "set") {
		t.Fatalf("config help missing subcommands:\n%s", help.String())
	}
	got := Complete([]string{"config"}, CompletionOptions{})
	for _, want := range []string{"show", "get", "set"} {
		if !slices.Contains(got, want) {
			t.Fatalf("config completions missing %q: %v", want, got)
		}
	}
}

func TestConfigCommandEdgesAndValueParsing(t *testing.T) {
	lockAppSeams(t)
	var out bytes.Buffer
	if err := configCommand(context.Background(), nil, &out, &fakeStarter{}); err != nil {
		t.Fatalf("config help: %v", err)
	}
	if !strings.Contains(out.String(), "usage: hasp config") {
		t.Fatalf("config help output = %q", out.String())
	}
	if err := configCommand(context.Background(), []string{"unknown"}, &out, &fakeStarter{}); err == nil {
		t.Fatal("expected unknown config subcommand")
	}
	if err := configShowCommand(context.Background(), []string{"extra"}, &out, &fakeStarter{}); err == nil {
		t.Fatal("expected config show usage error")
	}
	if err := configGetCommand(context.Background(), nil, &out, &fakeStarter{}); err == nil {
		t.Fatal("expected config get usage error")
	}
	if err := configSetCommand(context.Background(), []string{"only-key"}, &out, &fakeStarter{}); err == nil {
		t.Fatal("expected config set usage error")
	}
	if _, err := parseConfigCLIValue("[not-json"); err == nil {
		t.Fatal("expected config array decode error")
	}
	for raw, want := range map[string]any{
		"":             "",
		"true":         true,
		"false":        false,
		"42":           42,
		`["a","b"]`:    []string{"a", "b"},
		"plain-string": "plain-string",
	} {
		got, err := parseConfigCLIValue(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("parse %q = %#v, want %#v", raw, got, want)
		}
	}
}
