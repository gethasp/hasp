package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func appendSecretAuditCLI(eventType string, details map[string]any) {
	appendAudit(eventType, "user", details)
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
	if envTruthy(envAgentSafeMode) {
		projectRoot := strings.TrimSpace(os.Getenv(envAgentProjectRoot))
		consumers := []string{}
		if name := strings.TrimSpace(os.Getenv(envAgentConsumer)); name != "" {
			consumers = append(consumers, name)
		}
		return secretPlaintextPolicy{Active: true, Source: "env", SessionToken: strings.TrimSpace(os.Getenv(envSessionToken)), ProjectRoot: projectRoot, AgentConsumers: consumers}, nil
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

func secretSessionFromEnv(ctx context.Context) (runtime.SessionView, string, bool, error) {
	token := strings.TrimSpace(os.Getenv(envSessionToken))
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
	if current, err := secretCurrentUserFn(); err == nil {
		if strings.TrimSpace(current.Username) != "" {
			return current.Username
		}
	}
	if value := strings.TrimSpace(os.Getenv("USER")); value != "" {
		return value
	}
	return "unknown"
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
