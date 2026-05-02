package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// secretPlaintextInteractiveTTL is the lifetime of an inline TTY-confirmed
// plaintext grant. Matches the documented operator UX so the prompt copy
// (`Grant 60s plaintext ... [y/N]`) does not drift from the underlying grant.
const secretPlaintextInteractiveTTL = 60 * time.Second

var grantPlaintextUseFn = (*store.Handle).GrantPlaintextUse

// secretPlaintextDeps captures the side-effecting hooks the interactive
// plaintext policy enforcement needs. Construction is explicit at the call
// site (production gets defaultSecretPlaintextDeps; tests pass tighter
// stubs), which makes the seam visible and removes the need for a
// package-level mutable var.
type secretPlaintextDeps struct {
	// Confirm prompts the operator and returns (granted, error). The
	// returned bool semantically maps to "operator typed y/yes".
	Confirm func(stderr io.Writer, stdin io.Reader, prompt string) (bool, error)
	// IsTerminal lets the default Confirm decide whether to even attempt
	// reading from stdin. Tests can force this to true in CI.
	IsTerminal func() bool
}

func defaultSecretPlaintextDeps() secretPlaintextDeps {
	deps := secretPlaintextDeps{IsTerminal: defaultStderrIsTerminal}
	deps.Confirm = func(stderr io.Writer, stdin io.Reader, prompt string) (bool, error) {
		return defaultPlaintextTTYConfirmWithDeps(stderr, stdin, prompt, deps.IsTerminal)
	}
	return deps
}

func defaultStderrIsTerminal() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func defaultPlaintextTTYConfirmWithDeps(stderr io.Writer, stdin io.Reader, prompt string, isTerminal func() bool) (bool, error) {
	if isTerminal == nil || !isTerminal() {
		return false, nil
	}
	if stdin == nil {
		return false, nil
	}
	if _, err := fmt.Fprint(stderr, prompt); err != nil {
		return false, err
	}
	reader := bufio.NewReader(stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes", nil
}

func appendSecretAuditCLI(eventType string, details map[string]any) {
	auditlog.AppendCLI(eventType, details)
}

// enforceSecretPlaintextPolicyInteractive wraps enforceSecretPlaintextPolicy
// with an inline TTY confirm. When the strict policy would block (and the
// operator could otherwise type out a grant-plaintext command with the same
// session token), we prompt once for a 60-second one-shot grant and retry.
// Anything other than an explicit "y"/"yes" leaves the original block error
// intact, so scripts and IO-error paths still see the actionable message.
func enforceSecretPlaintextPolicyInteractive(ctx context.Context, handle *store.Handle, itemName string, action store.PlaintextAction, stdin io.Reader, stderr io.Writer, deps secretPlaintextDeps) error {
	err := enforceSecretPlaintextPolicy(ctx, handle, itemName, action)
	if err == nil {
		return nil
	}
	policy, perr := secretPlaintextPolicyForContext(ctx, handle)
	if perr != nil || !policy.Active || policy.SessionToken == "" {
		return err
	}
	if deps.Confirm == nil {
		return err
	}
	prompt := fmt.Sprintf("Grant 60s plaintext %s for %s? [y/N] ", action, itemName)
	confirmed, confirmErr := deps.Confirm(stderr, stdin, prompt)
	if confirmErr != nil || !confirmed {
		return err
	}
	if _, gerr := grantPlaintextUseFn(handle, policy.SessionToken, itemName, action, "user", store.GrantOnce, secretPlaintextInteractiveTTL); gerr != nil {
		return gerr
	}
	return enforceSecretPlaintextPolicy(ctx, handle, itemName, action)
}

func enforceSecretPlaintextPolicy(ctx context.Context, handle *store.Handle, itemName string, action store.PlaintextAction) error {
	policy, err := secretPlaintextPolicyForContext(ctx, handle)
	if err != nil {
		return err
	}
	if !policy.Active {
		return nil
	}
	if policy.SessionToken != "" && handle.PlaintextGrantActive(policy.SessionToken, itemName, action) {
		if err := handle.ConsumePlaintextGrant(policy.SessionToken, itemName, action); err != nil {
			return err
		}
		appendSecretAuditCLI(audit.EventOverride, map[string]any{
			"action":           "secret.get.plaintext_grant_used",
			"surface":          "cli",
			"actor_label":      secretActorLabel(),
			"item_name":        itemName,
			"plaintext_action": action,
			"policy_source":    policy.Source,
			"project_root":     policy.ProjectRoot,
			"agent_consumers":  policy.AgentConsumers,
			"session_token":    policy.SessionToken,
		})
		return nil
	}
	appendSecretAuditCLI(audit.EventDeny, map[string]any{
		"action":           "secret.get.plaintext_blocked",
		"surface":          "cli",
		"actor_label":      secretActorLabel(),
		"item_name":        itemName,
		"plaintext_action": action,
		"policy_source":    policy.Source,
		"project_root":     policy.ProjectRoot,
		"agent_consumers":  policy.AgentConsumers,
		"session_token":    policy.SessionToken,
	})
	if policy.SessionToken != "" {
		return fmt.Errorf("plaintext secret access is blocked in agent-safe mode; grant one-time access with: hasp session grant-plaintext --token %s --item %s --action %s", policy.SessionToken, itemName, action)
	}
	return fmt.Errorf("plaintext secret access is blocked in agent-safe mode; launch the agent through 'hasp agent launch' or 'hasp agent shell' so HASP can attach a broker-held approval grant")
}

func secretPlaintextPolicyForContext(ctx context.Context, handle *store.Handle) (secretPlaintextPolicy, error) {
	if session, token, ok, err := secretSessionFromProcessTree(ctx); err != nil {
		return secretPlaintextPolicy{}, err
	} else if ok && session.AgentSafe {
		consumers := []string{}
		if strings.TrimSpace(session.ConsumerName) != "" {
			consumers = []string{session.ConsumerName}
		}
		return secretPlaintextPolicy{
			Active:         true,
			Source:         "process_tree",
			SessionToken:   token,
			ProjectRoot:    session.ProjectRoot,
			AgentConsumers: consumers,
		}, nil
	}
	if session, token, ok, err := secretSessionFromEnv(ctx); err != nil {
		return secretPlaintextPolicy{}, err
	} else if ok && session.AgentSafe {
		consumers := []string{}
		if strings.TrimSpace(session.ConsumerName) != "" {
			consumers = []string{session.ConsumerName}
		}
		return secretPlaintextPolicy{
			Active:         true,
			Source:         "session",
			SessionToken:   token,
			ProjectRoot:    session.ProjectRoot,
			AgentConsumers: consumers,
		}, nil
	}
	if envTruthy(secrettypes.EnvAgentSafeMode) {
		projectRoot := strings.TrimSpace(os.Getenv(secrettypes.EnvAgentProjectRoot))
		consumers := []string{}
		if name := strings.TrimSpace(os.Getenv(secrettypes.EnvAgentConsumer)); name != "" {
			consumers = append(consumers, name)
		}
		return secretPlaintextPolicy{Active: true, Source: "env", SessionToken: strings.TrimSpace(os.Getenv(secrettypes.EnvSessionToken)), ProjectRoot: projectRoot, AgentConsumers: consumers}, nil
	}
	root, inRepo, err := secretProjectContext(ctx, "")
	if err != nil || !inRepo {
		return secretPlaintextPolicy{}, err
	}
	consumers := secretListAgentsFn(handle)
	matches := make([]string, 0)
	for _, consumer := range consumers {
		if consumer.ProjectRoot == root {
			matches = append(matches, consumer.Name)
		}
	}
	if len(matches) == 0 {
		return secretPlaintextPolicy{}, nil
	}
	return secretPlaintextPolicy{
		Active:         true,
		Source:         "connected_agent_repo",
		ProjectRoot:    root,
		AgentConsumers: matches,
	}, nil
}

func envTruthy(key string) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch value {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func parsePlaintextAction(value string) (store.PlaintextAction, error) {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case string(store.PlaintextReveal):
		return store.PlaintextReveal, nil
	case string(store.PlaintextCopy):
		return store.PlaintextCopy, nil
	default:
		return "", fmt.Errorf("unsupported plaintext action %q", value)
	}
}

func parseSecretMutationAction(value string) (store.SecretMutationAction, error) {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case string(store.SecretMutationDelete):
		return store.SecretMutationDelete, nil
	case string(store.SecretMutationExpose):
		return store.SecretMutationExpose, nil
	case string(store.SecretMutationHide):
		return store.SecretMutationHide, nil
	default:
		return "", fmt.Errorf("unsupported secret mutation action %q", value)
	}
}

func secretSessionFromEnv(ctx context.Context) (runtime.SessionView, string, bool, error) {
	token := strings.TrimSpace(os.Getenv(secrettypes.EnvSessionToken))
	if token == "" {
		return runtime.SessionView{}, "", false, nil
	}
	manager, err := secretNewManagerFn()
	if err != nil {
		return runtime.SessionView{}, "", false, err
	}
	client, err := secretDialRuntimeFn(ctx, manager.SocketPath())
	if err != nil {
		return runtime.SessionView{}, "", false, err
	}
	defer client.Close()
	reply, err := client.ResolveSession(ctx, token)
	if err != nil {
		return runtime.SessionView{}, "", false, err
	}
	return reply.Session, token, true, nil
}

func secretSessionFromProcessTree(ctx context.Context) (runtime.SessionView, string, bool, error) {
	manager, err := secretNewManagerFn()
	if err != nil {
		return runtime.SessionView{}, "", false, err
	}
	client, err := secretDialRuntimeFn(ctx, manager.SocketPath())
	if err != nil {
		return runtime.SessionView{}, "", false, nil
	}
	defer client.Close()
	reply, err := client.ResolveProcess(ctx, os.Getpid())
	if err != nil || !reply.Found {
		return runtime.SessionView{}, "", false, err
	}
	return reply.Session, reply.SessionToken, true, nil
}

func secretActorLabel() string {
	return auditlog.ActorLabel()
}

func copySecretToClipboard(value []byte) error {
	commands := [][]string{}
	switch secretRuntimeGOOS {
	case "darwin":
		commands = append(commands, []string{"pbcopy"})
	default:
		commands = append(commands,
			[]string{"wl-copy"},
			[]string{"xclip", "-selection", "clipboard"},
			[]string{"xsel", "--clipboard", "--input"},
		)
	}
	lastErr := errors.New("no clipboard command available")
	for _, argv := range commands {
		cmd := secretExecCommandFn(argv[0], argv[1:]...)
		cmd.Stdin = strings.NewReader(string(value))
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Run(); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}
