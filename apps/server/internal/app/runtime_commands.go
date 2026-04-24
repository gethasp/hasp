package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var appCanonicalProjectRootFn = store.CanonicalProjectRoot
var openVaultHandleFn = openVaultHandle
var sessionGrantPlaintextApproveFn = confirmPlaintextGrant
var confirmPlaintextGrantGOOS = goruntime.GOOS
var confirmPlaintextGrantCommandFn = exec.Command
var confirmPlaintextGrantUnderTestFn = func() bool {
	return strings.HasSuffix(strings.TrimSpace(filepath.Base(os.Args[0])), ".test")
}
var sessionGrantPlaintextUseFn = func(handle *store.Handle, token string, itemName string, action store.PlaintextAction, window time.Duration) (store.PlaintextGrant, error) {
	return handle.GrantPlaintextUse(token, itemName, action, "user", store.GrantOnce, window)
}
var revokeAllGrantsFn = (*store.Handle).RevokeAllGrants

func exportBackupCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("export-backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	outputPath := fs.String("output", "", "")
	passphrase := fs.String("recovery-passphrase", os.Getenv("HASP_BACKUP_PASSPHRASE"), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *outputPath == "" || *passphrase == "" {
		return errors.New("usage: hasp export-backup --output <path> --recovery-passphrase <passphrase>")
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	checkpoint, err := handle.ExportBackup(ctx, *outputPath, *passphrase)
	if err != nil {
		return err
	}
	payload := map[string]any{"output_path": *outputPath, "checkpoint": checkpoint}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderBackupResult(w, "Backup exported", "Wrote an encrypted HASP backup.", *outputPath, checkpoint)
	})
}

func restoreBackupCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("restore-backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	inputPath := fs.String("input", "", "")
	passphrase := fs.String("recovery-passphrase", os.Getenv("HASP_BACKUP_PASSPHRASE"), "")
	masterPassword := fs.String("master-password", os.Getenv("HASP_MASTER_PASSWORD"), "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" || *passphrase == "" || *masterPassword == "" {
		return errors.New("usage: hasp restore-backup --input <path> --recovery-passphrase <passphrase> --master-password <password>")
	}
	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return err
	}
	checkpoint, err := vaultStore.RestoreBackup(ctx, *inputPath, *passphrase, *masterPassword)
	if err != nil {
		return err
	}
	payload := map[string]any{"input_path": *inputPath, "checkpoint": checkpoint}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderBackupResult(w, "Backup restored", "Restored the HASP vault from an encrypted backup.", *inputPath, checkpoint)
	})
}

func tuiCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", ".", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	binding, visible, _, err := ensureProjectBinding(ctx, handle, *projectRoot)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(map[string]any{
			"binding":       binding,
			"visible":       visible,
			"vault_items":   len(handle.ListItems()),
			"project_root":  binding.CanonicalRoot,
			"visible_count": len(visible),
		})
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "HASP TUI\tproject=%s\n", binding.CanonicalRoot)
	fmt.Fprintf(tw, "binding_id\t%s\n", binding.ID)
	fmt.Fprintf(tw, "visible_refs\t%d\n", len(visible))
	items := handle.ListItems()
	fmt.Fprintf(tw, "vault_items\t%d\n", len(items))
	for _, ref := range visible {
		fmt.Fprintf(tw, "ref\t%s\t%s\t%s\n", ref.Alias, ref.Kind, ref.PolicyLevel)
	}
	return tw.Flush()
}

func daemonCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		return printHelpTopic(stdout, []string{"daemon"})
	}
	manager, err := runtime.NewManager()
	if err != nil {
		return err
	}
	switch args[0] {
	case "serve":
		return manager.RunDaemon(ctx)
	case "start":
		return manager.StartDaemon(ctx)
	case "stop":
		return manager.StopDaemon()
	case "status":
		return statusCommandWithArgs(ctx, args[1:], stdout, s)
	default:
		return fmt.Errorf("unknown daemon subcommand %q", args[0])
	}
}

func pingCommand(ctx context.Context, stdout io.Writer, s starter) error {
	return pingCommandWithArgs(ctx, nil, stdout, s)
}

func pingCommandWithArgs(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()

	reply, err := client.Ping(ctx)
	if err != nil {
		return err
	}
	return renderPingJSONOrHuman(stdout, *jsonOutput, reply)
}

func statusCommand(ctx context.Context, stdout io.Writer, s starter) error {
	return statusCommandWithArgs(ctx, nil, stdout, s)
}

func statusCommandWithArgs(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()

	reply, err := client.Status(ctx)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(reply)
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "socket\t%s\n", reply.SocketPath)
	fmt.Fprintf(tw, "pid\t%d\n", reply.PID)
	fmt.Fprintf(tw, "started_at\t%s\n", reply.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(tw, "active_sessions\t%d\n", reply.ActiveSessions)
	fmt.Fprintf(tw, "audit_degraded\t%t\n", reply.AuditDegraded)
	if reply.AuditDegradedAt != nil {
		fmt.Fprintf(tw, "audit_degraded_at\t%s\n", reply.AuditDegradedAt.Format(time.RFC3339))
	}
	return tw.Flush()
}

func vaultCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		return printHelpTopic(stdout, []string{"vault"})
	}
	switch args[0] {
	case "lock":
		return vaultLockCommand(ctx, args[1:], stdout, s)
	default:
		return fmt.Errorf("unknown vault subcommand %q", args[0])
	}
}

func vaultLockCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("vault lock", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp vault lock [--json]")
	}
	revokedSessions := 0
	if s != nil {
		client, err := s.Connect(ctx)
		if err == nil && client != nil {
			reply, lockErr := client.LockVault(ctx)
			_ = client.Close()
			if lockErr != nil {
				return lockErr
			}
			revokedSessions = reply.RevokedCount
		}
	}
	revokedGrants := 0
	if handle, openErr := openVaultHandleFn(ctx); openErr == nil {
		if count, revokeErr := revokeAllGrantsFn(handle); revokeErr != nil {
			return revokeErr
		} else {
			revokedGrants = count
		}
	}
	payload := map[string]any{
		"vault_state":      "locked",
		"revoked_sessions": revokedSessions,
		"revoked_grants":   revokedGrants,
	}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(w, "Vault locked", "Revoked active sessions and grant material.",
			cliPair("Vault state", "locked"),
			cliPair("Revoked sessions", fmt.Sprintf("%d", revokedSessions)),
			cliPair("Revoked grants", fmt.Sprintf("%d", revokedGrants)),
		)
	})
}

func sessionCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		return printHelpTopic(stdout, []string{"session"})
	}
	switch args[0] {
	case "open":
		return sessionOpenCommand(ctx, args[1:], stdout, s)
	case "grant-plaintext":
		return sessionGrantPlaintextCommand(ctx, args[1:], stdout, s)
	case "resolve":
		return sessionResolveCommand(ctx, args[1:], stdout, s)
	case "revoke":
		return sessionRevokeCommand(ctx, args[1:], stdout, s)
	default:
		return fmt.Errorf("unknown session subcommand %q", args[0])
	}
}

func sessionOpenCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("session open", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	hostLabel := fs.String("host-label", "generic-client", "")
	projectRoot := fs.String("project-root", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	canonicalRoot, err := appCanonicalProjectRootFn(ctx, *projectRoot)
	if err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	if _, _, _, err := ensureProjectBinding(ctx, handle, canonicalRoot); err != nil {
		return err
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()

	reply, err := client.OpenSession(ctx, runtime.OpenSessionRequest{
		HostLabel:   *hostLabel,
		ProjectRoot: canonicalRoot,
		TTLSeconds:  int(runtime.DefaultSessionTTL.Seconds()),
	})
	if err != nil {
		return err
	}
	safe := struct {
		SessionID   string    `json:"session_id"`
		HostLabel   string    `json:"host_label"`
		ProjectRoot string    `json:"project_root"`
		ExpiresAt   time.Time `json:"expires_at"`
	}{
		SessionID:   reply.SessionID,
		HostLabel:   reply.HostLabel,
		ProjectRoot: reply.ProjectRoot,
		ExpiresAt:   reply.ExpiresAt,
	}
	return renderJSONOrHuman(stdout, *jsonOutput, safe, func(w io.Writer) error {
		return renderSessionOpenResult(w, safe.SessionID, safe.HostLabel, safe.ProjectRoot, safe.ExpiresAt.Format(timeRFC3339))
	})
}

func sessionGrantPlaintextCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("session grant-plaintext", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	token := fs.String("token", strings.TrimSpace(os.Getenv(envSessionToken)), "")
	itemName := fs.String("item", "", "")
	action := fs.String("action", "", "")
	scope := fs.String("scope", string(store.GrantOnce), "")
	window := fs.Duration("grant-window", store.DefaultPlaintextGrantTTL, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" || strings.TrimSpace(*itemName) == "" || strings.TrimSpace(*action) == "" {
		return errors.New("usage: hasp session grant-plaintext --token <token> --item <name> --action reveal|copy [--scope once] [--grant-window 60s]")
	}
	plaintextAction, err := parsePlaintextAction(*action)
	if err != nil {
		return err
	}
	if parseGrantScope(*scope) != store.GrantOnce {
		return fmt.Errorf("plaintext grants only support --scope %q", store.GrantOnce)
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()
	reply, err := client.ResolveSession(ctx, *token)
	if err != nil {
		return fmt.Errorf("resolve session: %w", err)
	}
	if !reply.Session.AgentSafe {
		return errors.New("plaintext grants require an agent-safe session")
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	item, err := secretGetItemFn(handle, strings.TrimSpace(*itemName))
	if err != nil {
		return err
	}
	if err := sessionGrantPlaintextApproveFn(reply.Session, item.Name, plaintextAction); err != nil {
		return err
	}
	grant, err := sessionGrantPlaintextUseFn(handle, *token, item.Name, plaintextAction, *window)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"session_id":         reply.Session.ID,
		"session_host_label": reply.Session.HostLabel,
		"project_root":       reply.Session.ProjectRoot,
		"item_name":          item.Name,
		"plaintext_action":   plaintextAction,
		"scope":              grant.Scope,
		"expires_at":         grant.ExpiresAt,
	}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(w, "Plaintext grant", "Granted one protected plaintext access path.",
			cliPair("Item", item.Name),
			cliPair("Action", string(plaintextAction)),
			cliPair("Scope", string(grant.Scope)),
			cliPair("Session", reply.Session.HostLabel),
		)
	})
}

func confirmPlaintextGrant(session runtime.SessionView, itemName string, action store.PlaintextAction) error {
	if confirmPlaintextGrantUnderTestFn() {
		return nil
	}
	projectRoot := session.ProjectRoot
	if strings.TrimSpace(projectRoot) == "" {
		projectRoot = "(no project root)"
	}
	if confirmPlaintextGrantGOOS != "darwin" {
		file, ok := stdinFile(os.Stdin)
		if !ok || !secretIsCharDeviceFn(file) {
			return errors.New("plaintext grants require local interactive operator approval")
		}
		phrase := fmt.Sprintf("grant %s %s", action, itemName)
		if _, err := fmt.Fprintf(os.Stdout, "Approve one-time %s of %s for %s\nProject: %s\nType %q to approve: ", action, itemName, session.HostLabel, projectRoot, phrase); err != nil {
			return err
		}
		answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if strings.TrimSpace(answer) != phrase {
			return errors.New("plaintext grant approval was cancelled")
		}
		return nil
	}
	script := fmt.Sprintf(`display dialog "Allow one-time %s of %s for %s?\n\nProject: %s" buttons {"Cancel", "Allow"} default button "Allow" with icon caution`,
		action, itemName, session.HostLabel, projectRoot,
	)
	cmd := confirmPlaintextGrantCommandFn("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		return errors.New("plaintext grant approval was cancelled")
	}
	return nil
}

func sessionRevokeCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("session revoke", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	token := fs.String("token", "", "")
	all := fs.Bool("all", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *all && *token != "" {
		return errors.New("choose either --all or --token")
	}
	if !*all && *token == "" {
		return errors.New("usage: hasp session revoke (--token <token> | --all)")
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()

	if *all {
		reply, err := client.RevokeAllSessions(ctx)
		if err != nil {
			return err
		}
		revokedGrants := 0
		if handle, openErr := openVaultHandleFn(ctx); openErr == nil {
			if count, revokeErr := revokeAllGrantsFn(handle); revokeErr != nil {
				return revokeErr
			} else {
				revokedGrants = count
			}
		}
		payload := map[string]any{"outcome": "revoked_all", "revoked_sessions": reply.RevokedCount, "revoked_grants": revokedGrants}
		return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
			return renderSimpleAction(w, "Sessions revoked", "Revoked all daemon-backed sessions.",
				cliPair("Outcome", "revoked_all"),
				cliPair("Revoked sessions", fmt.Sprintf("%d", reply.RevokedCount)),
				cliPair("Revoked grants", fmt.Sprintf("%d", revokedGrants)),
			)
		})
	}

	if err := client.RevokeSession(ctx, *token); err != nil {
		return err
	}
	payload := map[string]any{"token": *token, "outcome": "revoked"}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(w, "Session revoked", "Revoked the daemon-backed session.",
			cliPair("Token", *token),
			cliPair("Outcome", "revoked"),
		)
	})
}

func sessionResolveCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("session resolve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	token := fs.String("token", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		return errors.New("usage: hasp session resolve --token <token>")
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()

	reply, err := client.ResolveSession(ctx, *token)
	if err != nil {
		return err
	}
	return renderJSONOrHuman(stdout, *jsonOutput, reply, func(w io.Writer) error {
		return renderSessionResolveResult(w, reply)
	})
}

func ensureClient(ctx context.Context, s starter) (*runtime.Client, error) {
	if err := s.EnsureDaemon(ctx); err != nil {
		return nil, err
	}
	return s.Connect(ctx)
}

func openVaultHandle(ctx context.Context) (*store.Handle, error) {
	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return nil, err
	}
	password, err := loadMasterPassword()
	if err == nil {
		return openStoreWithPasswordFn(ctx, vaultStore, password)
	}
	handle, unlockErr := vaultStore.OpenWithConvenienceUnlock(ctx)
	if unlockErr != nil && errors.Is(unlockErr, store.ErrKeyringUnavailable) {
		return nil, fmt.Errorf("HASP_MASTER_PASSWORD is not set and convenience unlock is unavailable")
	}
	return handle, unlockErr
}
