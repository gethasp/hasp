package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// hasp-7nkz: Today, an agent-safe block on `secret reveal` forces the
// operator through 4 commands and a token paste. When a TTY is attached,
// `enforceSecretPlaintextPolicyInteractive` should prompt `[y/N]` once,
// mint a 60s one-shot grant on yes, and proceed — keeping
// `session grant-plaintext` for non-interactive scripts.

func setupAgentSafeSession(t *testing.T) (*store.Handle, string) {
	t.Helper()
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := handle.UpsertItem("API_TOKEN", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	starter := newDaemonTestStarter(t)
	client, err := starter.Connect(context.Background())
	if err != nil {
		t.Fatalf("dial daemon: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	reply, err := client.OpenSession(context.Background(), runtime.OpenSessionRequest{
		HostLabel:    "interactive-grant-test",
		ProjectRoot:  t.TempDir(),
		TTLSeconds:   int(runtime.DefaultSessionTTL.Seconds()),
		AgentSafe:    true,
		ConsumerName: "claude-code",
	})
	if err != nil {
		t.Fatalf("open agent-safe session: %v", err)
	}
	t.Setenv(envAgentSafeMode, "1")
	t.Setenv(envSessionToken, reply.SessionToken)
	return handle, reply.SessionToken
}

func TestEnforceSecretPlaintextPolicyInteractiveTTYYesGrantsAndProceeds(t *testing.T) {
	lockAppSeams(t)
	handle, _ := setupAgentSafeSession(t)

	var prompted string
	deps := secretPlaintextDeps{
		Confirm: func(_ io.Writer, _ io.Reader, prompt string) (bool, error) {
			prompted = prompt
			return true, nil
		},
	}

	if err := enforceSecretPlaintextPolicyInteractive(context.Background(), handle, "API_TOKEN", store.PlaintextReveal, nil, io.Discard, deps); err != nil {
		t.Fatalf("expected interactive grant to proceed, got %v", err)
	}
	if !strings.Contains(prompted, "API_TOKEN") || !strings.Contains(strings.ToLower(prompted), "[y/n]") {
		t.Fatalf("unexpected prompt: %q", prompted)
	}
}

func TestEnforceSecretPlaintextPolicyInteractiveTTYNoStillBlocks(t *testing.T) {
	lockAppSeams(t)
	handle, sessionToken := setupAgentSafeSession(t)

	deps := secretPlaintextDeps{
		Confirm: func(_ io.Writer, _ io.Reader, _ string) (bool, error) { return false, nil },
	}

	err := enforceSecretPlaintextPolicyInteractive(context.Background(), handle, "API_TOKEN", store.PlaintextReveal, nil, io.Discard, deps)
	if err == nil {
		t.Fatal("expected block when operator declines interactive grant")
	}
	if !strings.Contains(err.Error(), "grant-plaintext --item API_TOKEN --action reveal") || strings.Contains(err.Error(), sessionToken) {
		t.Fatalf("expected fallback error to mention token-safe grant-plaintext guidance, got %v", err)
	}
}

func TestEnforceSecretPlaintextPolicyInteractiveConfirmErrorPropagates(t *testing.T) {
	lockAppSeams(t)
	handle, _ := setupAgentSafeSession(t)

	deps := secretPlaintextDeps{
		Confirm: func(_ io.Writer, _ io.Reader, _ string) (bool, error) {
			return false, errors.New("tty broken")
		},
	}

	err := enforceSecretPlaintextPolicyInteractive(context.Background(), handle, "API_TOKEN", store.PlaintextReveal, nil, io.Discard, deps)
	// On confirm error we keep the original block error rather than masking it
	// with the IO failure — operators still see the actionable grant-plaintext
	// hint.
	if err == nil {
		t.Fatal("expected block error after confirm IO failure")
	}
	if strings.Contains(err.Error(), "tty broken") {
		t.Fatalf("expected confirm IO error to be suppressed, got %v", err)
	}
}

func TestEnforceSecretPlaintextPolicyInteractivePassThroughWhenNotBlocked(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := handle.UpsertItem("API_TOKEN", store.ItemKindKV, []byte("abc123"), store.ItemMetadata{}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	confirmCalled := false
	deps := secretPlaintextDeps{
		Confirm: func(_ io.Writer, _ io.Reader, _ string) (bool, error) {
			confirmCalled = true
			return true, nil
		},
	}

	if err := enforceSecretPlaintextPolicyInteractive(context.Background(), handle, "API_TOKEN", store.PlaintextReveal, nil, io.Discard, deps); err != nil {
		t.Fatalf("expected pass-through when no agent-safe policy active, got %v", err)
	}
	if confirmCalled {
		t.Fatal("did not expect TTY confirm when policy is inactive")
	}
}
