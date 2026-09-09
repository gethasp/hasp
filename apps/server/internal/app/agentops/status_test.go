package agentops

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestStatusValidatesArgumentsAndPropagatesDiagnosticFailures(t *testing.T) {
	ctx := context.Background()
	for _, args := range [][]string{{"status"}, {"status", "claude-code", "extra"}, {"status", "claude-code", "--invalid"}} {
		if err := AgentCommand(ctx, Deps{}, args, nil, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	if err := AgentCommand(ctx, Deps{}, []string{"status", "claude-code"}, nil, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing diagnostics: %v", err)
	}
	want := errors.New("lookup failed")
	deps := fullAgentDeps(t)
	deps.AgentStatus = func(context.Context, string) (map[string]any, error) { return nil, want }
	if err := AgentCommand(ctx, deps, []string{"status", "claude-code"}, nil, io.Discard, io.Discard); !errors.Is(err, want) {
		t.Fatalf("lookup error: %v", err)
	}
}

func TestStatusHumanOutputSelectsPublicDiagnostics(t *testing.T) {
	deps := fullAgentDeps(t)
	deps.AgentStatus = func(_ context.Context, name string) (map[string]any, error) {
		if name != "claude-code" {
			t.Fatalf("wrong client: %s", name)
		}
		return map[string]any{"agent_id": name, "client_installed": true, "connection": "not_observed", "private_field": "omit this"}, nil
	}
	want := [][2]string{{"agent_id", "claude-code"}, {"client_installed", "true"}, {"connection", "not_observed"}}
	rendered := false
	deps.RenderSimpleAction = func(_ context.Context, _ io.Writer, title, lead string, pairs ...[2]string) error {
		rendered = true
		if title != "Agent status" || !strings.Contains(lead, "client's shell tool") || !reflect.DeepEqual(pairs, want) {
			t.Fatalf("human diagnostics: %s %s %v", title, lead, pairs)
		}
		return io.ErrClosedPipe
	}
	err := AgentCommand(context.Background(), deps, []string{"status", "claude-code"}, nil, io.Discard, io.Discard)
	if !rendered || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("render error: %t %v", rendered, err)
	}
}
