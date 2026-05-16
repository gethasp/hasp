package sessionops

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestSessionRevokeHumanOutputOmitsRawToken(t *testing.T) {
	deps := fullSessionDeps(t, &fakeSessionRPC{})

	var rendered string
	deps.RenderJSONOrHuman = func(_ context.Context, _ io.Writer, _ bool, _ any, human func(io.Writer) error) error {
		var out bytes.Buffer
		if err := human(&out); err != nil {
			return err
		}
		rendered = out.String()
		return nil
	}

	if err := sessionRevoke(context.Background(), deps, []string{"--token", "tok-secret"}, io.Discard); err != nil {
		t.Fatalf("session revoke human: %v", err)
	}
	if strings.Contains(rendered, "tok-secret") {
		t.Fatalf("human revoke output leaked raw session token: %q", rendered)
	}
}

func TestSessionRevokeJSONPayloadOmitsRawToken(t *testing.T) {
	deps := fullSessionDeps(t, &fakeSessionRPC{})

	var payload map[string]any
	deps.RenderJSONOrHuman = func(_ context.Context, _ io.Writer, _ bool, value any, _ func(io.Writer) error) error {
		var ok bool
		payload, ok = value.(map[string]any)
		if !ok {
			t.Fatalf("expected revoke payload map, got %T", value)
		}
		return nil
	}

	if err := sessionRevoke(context.Background(), deps, []string{"--json", "--token", "tok-secret"}, io.Discard); err != nil {
		t.Fatalf("session revoke json: %v", err)
	}
	if _, ok := payload["token"]; ok {
		t.Fatalf("json revoke payload leaked raw session token: %+v", payload)
	}
}
