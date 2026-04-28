package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var appCanonicalProjectRootFn = store.CanonicalProjectRoot
var openVaultHandleFn = openVaultHandle

// sessionLocalDeps bundles the seams that personalise session-related
// CLI commands: the plaintext-grant approval prompt (Approve), the
// store-side grant issuance (UseGrant) and the local-user lookup that
// "session list --mine" filters on. Tests construct a local instance
// to inject deterministic outcomes without touching package-level vars.
type sessionLocalDeps struct {
	Approve     func(session runtime.SessionView, itemName string, action store.PlaintextAction) error
	UseGrant    func(handle *store.Handle, token string, itemName string, action store.PlaintextAction, window time.Duration) (store.PlaintextGrant, error)
	LocalUser   func() (string, error)
}

func defaultSessionLocalDeps() sessionLocalDeps {
	return sessionLocalDeps{
		Approve: confirmPlaintextGrant,
		UseGrant: func(handle *store.Handle, token string, itemName string, action store.PlaintextAction, window time.Duration) (store.PlaintextGrant, error) {
			return handle.GrantPlaintextUse(token, itemName, action, "user", store.GrantOnce, window)
		},
		LocalUser: func() (string, error) {
			u, err := user.Current()
			if err != nil {
				return "", err
			}
			if u.Username != "" {
				return u.Username, nil
			}
			return u.Uid, nil
		},
	}
}

// confirmPlaintextGrantDeps wires the platform inputs that the operator
// approval prompt depends on (current GOOS for choosing macOS osascript vs
// terminal flow, exec.Command factory for shelling osascript, UnderTest
// to short-circuit the whole prompt under "go test"). Tests build a local
// instance to drive each branch deterministically without holding the
// process-wide app-seam mutex.
type confirmPlaintextGrantDeps struct {
	GOOS      string
	Command   func(name string, arg ...string) *exec.Cmd
	UnderTest func() bool
}

func defaultConfirmPlaintextGrantDeps() confirmPlaintextGrantDeps {
	return confirmPlaintextGrantDeps{
		GOOS:    goruntime.GOOS,
		Command: exec.Command,
		UnderTest: func() bool {
			return strings.HasSuffix(strings.TrimSpace(filepath.Base(os.Args[0])), ".test")
		},
	}
}
// vaultGrantOpsDeps wires the store-handle operations that vault-lock,
// vault forget-device, and session revoke --all need to drop saved grants
// and convenience unlock state. Tests build a local instance to inject
// failure paths without touching package-level vars.
type vaultGrantOpsDeps struct {
	RevokeAllGrants          func(handle *store.Handle) (int, error)
	DisableConvenienceUnlock func(handle *store.Handle, ctx context.Context) (bool, error)
}

func defaultVaultGrantOpsDeps() vaultGrantOpsDeps {
	return vaultGrantOpsDeps{
		RevokeAllGrants: (*store.Handle).RevokeAllGrants,
		DisableConvenienceUnlock: func(h *store.Handle, ctx context.Context) (bool, error) {
			return h.DisableConvenienceUnlock(ctx)
		},
	}
}

func exportBackupCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("export-backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	outputPath := fs.String("output", "", "")
	// Unsafe argv forms: defined so flag.Parse doesn't reject them as unknown,
	// but checked post-parse to emit a helpful rejection message.
	argvPassphrase := fs.String("recovery-passphrase", "", "")
	// Safe forms.
	stdinFlag := fs.Bool("recovery-passphrase-stdin", false, "")
	fdFlag := fs.Int("recovery-passphrase-fd", -1, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Reject the unsafe argv form before doing anything else.
	if *argvPassphrase != "" {
		return errArgvPassphrase
	}
	if *outputPath == "" {
		return errors.New("usage: hasp export-backup --output <path> (--recovery-passphrase-stdin | --recovery-passphrase-fd N | HASP_BACKUP_PASSPHRASE)")
	}
	passphrase, err := readPassphrase(*stdinFlag, *fdFlag, os.Getenv("HASP_BACKUP_PASSPHRASE"), "HASP_BACKUP_PASSPHRASE")
	if err != nil {
		return err
	}
	expandedOutput, err := expandUserPath(strings.TrimSpace(*outputPath))
	if err != nil {
		return fmt.Errorf("--output: %w", err)
	}
	*outputPath = expandedOutput
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	checkpoint, err := handle.ExportBackup(ctx, *outputPath, passphrase)
	if err != nil {
		return err
	}
	payload := map[string]any{"output_path": *outputPath, "checkpoint": checkpoint}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderBackupResult(w, "Backup exported", "Wrote an encrypted HASP backup.", *outputPath, checkpoint)
	})
}

func restoreBackupCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("restore-backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	inputPath := fs.String("input", "", "")
	// Unsafe argv forms: defined so flag.Parse doesn't reject them as unknown,
	// but checked post-parse to emit a helpful rejection message.
	argvPassphrase := fs.String("recovery-passphrase", "", "")
	argvMasterPassword := fs.String("master-password", "", "")
	// Safe forms.
	stdinFlag := fs.Bool("recovery-passphrase-stdin", false, "")
	fdFlag := fs.Int("recovery-passphrase-fd", -1, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Reject the unsafe argv forms before doing anything else.
	if *argvPassphrase != "" {
		return errArgvPassphrase
	}
	if *argvMasterPassword != "" {
		return errArgvMasterPassword
	}
	if *inputPath == "" {
		return errors.New("usage: hasp restore-backup --input <path> (--recovery-passphrase-stdin | --recovery-passphrase-fd N | HASP_BACKUP_PASSPHRASE)")
	}
	passphrase, err := readPassphrase(*stdinFlag, *fdFlag, os.Getenv("HASP_BACKUP_PASSPHRASE"), "HASP_BACKUP_PASSPHRASE")
	if err != nil {
		return err
	}
	masterPassword := strings.TrimSpace(os.Getenv("HASP_MASTER_PASSWORD"))
	if masterPassword == "" {
		return errors.New("HASP_MASTER_PASSWORD must be set for restore-backup")
	}
	expandedInput, err := expandUserPath(strings.TrimSpace(*inputPath))
	if err != nil {
		return fmt.Errorf("--input: %w", err)
	}
	*inputPath = expandedInput
	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return err
	}
	checkpoint, err := vaultStore.RestoreBackup(ctx, *inputPath, passphrase, masterPassword)
	if err != nil {
		return err
	}
	payload := map[string]any{"input_path": *inputPath, "checkpoint": checkpoint}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderBackupResult(w, "Backup restored", "Restored the HASP vault from an encrypted backup.", *inputPath, checkpoint)
	})
}

func tuiCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", ".", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if stderr != nil {
		fmt.Fprintln(stderr, "warning: `hasp tui` is deprecated and prints a one-shot snapshot, not an interactive UI; use `hasp project status` for the structured project view.")
	}
	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return fmt.Errorf("--project-root: %w", err)
	}
	*projectRoot = expandedRoot
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	binding, visible, _, err := ensureProjectBinding(ctx, handle, *projectRoot)
	if err != nil {
		return err
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, map[string]any{
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
		if err := manager.StopDaemon(); err != nil {
			if strings.Contains(err.Error(), "process already finished") {
				return newAppError(errCodeInternal, "daemon was not running")
			}
			return err
		}
		return nil
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
	client := connectIfRunning(ctx, s)
	if client == nil {
		return renderNotRunning(stdout, *jsonOutput || globalFlagsFromContext(ctx).json)
	}
	defer client.Close()

	reply, err := client.Ping(ctx)
	if err != nil {
		return err
	}
	return renderPingJSONOrHuman(ctx, stdout, *jsonOutput, reply)
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
	client := connectIfRunning(ctx, s)
	if client == nil {
		return renderNotRunning(stdout, *jsonOutput || globalFlagsFromContext(ctx).json)
	}
	defer client.Close()

	reply, err := client.Status(ctx)
	if err != nil {
		return err
	}
	if *jsonOutput || globalFlagsFromContext(ctx).json {
		return writeJSONResponse(stdout, reply)
	}
	return renderStatusHuman(stdout, reply)
}

// renderStatusHuman writes the daemon status as a 2-space padded key/value
// table. Long socket paths are leading-ellipsis clipped against the live
// terminal width (hasp-hnf9) so narrow terminals don't wrap; JSON callers
// always see the full SocketPath.
func renderStatusHuman(stdout io.Writer, reply runtime.StatusResponse) error {
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	const socketKey = "socket"
	// Match the on-screen padding (key + minpad of 2) so the clip threshold
	// reflects what bytes actually print on this row.
	socketPath := clipForTerminal(reply.SocketPath, len(socketKey)+2, terminalColumnsFn())
	fmt.Fprintf(tw, "%s\t%s\n", socketKey, socketPath)
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
	case "forget-device":
		return vaultForgetDeviceCommand(ctx, args[1:], stdout)
	case "rekdf":
		return vaultRekdfCommand(ctx, args[1:], stdout)
	case "rekey":
		return vaultRekeyCommand(ctx, args[1:], stdout)
	default:
		return fmt.Errorf("unknown vault subcommand %q", args[0])
	}
}

func vaultRekeyCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("vault rekey", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp vault rekey [--json]")
	}
	oldPassword, err := loadMasterPassword()
	if err != nil {
		return fmt.Errorf("vault rekey requires HASP_MASTER_PASSWORD: %w", err)
	}
	newPassword, err := loadNewMasterPassword()
	if err != nil {
		return err
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	if err := handle.RekeyPassword(ctx, oldPassword, newPassword); err != nil {
		return err
	}
	payload := map[string]any{
		"vault_state":         "rekey_complete",
		"convenience_cleared": true,
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(ctx, w, "Vault password rotated",
			"Rewrapped the vault key under the new master password and cleared the saved keychain unlock.",
			cliPair("Vault state", "rekey_complete"),
			cliPair("Convenience unlock", "cleared"),
		)
	})
}

func loadNewMasterPassword() (string, error) {
	password := strings.TrimSpace(os.Getenv("HASP_NEW_MASTER_PASSWORD"))
	if password == "" {
		return "", errors.New("HASP_NEW_MASTER_PASSWORD must be set to the new master password")
	}
	return password, nil
}

func vaultRekdfCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("vault rekdf", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp vault rekdf [--json]")
	}
	password, err := loadMasterPassword()
	if err != nil {
		return fmt.Errorf("vault rekdf requires HASP_MASTER_PASSWORD: %w", err)
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	from, to, err := handle.RekdfWithPassword(ctx, password)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"vault_state": "rekdf_complete",
		"from_kdf":    from,
		"to_kdf":      to,
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(ctx, w, "Vault KDF rewritten",
			fmt.Sprintf("Re-derived the password wrap from %s to %s without rotating the underlying vault key.", from, to),
			cliPair("From KDF", from),
			cliPair("To KDF", to),
		)
	})
}

func vaultLockCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	return vaultLockCommandWithDeps(ctx, args, stdout, s, defaultVaultGrantOpsDeps())
}

func vaultLockCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, s starter, deps vaultGrantOpsDeps) error {
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
	convenienceState := "unchanged"
	if handle, openErr := openVaultHandleFn(ctx); openErr == nil {
		if count, revokeErr := deps.RevokeAllGrants(handle); revokeErr != nil {
			return revokeErr
		} else {
			revokedGrants = count
		}
		hadWrap, forgetErr := deps.DisableConvenienceUnlock(handle, ctx)
		if forgetErr != nil {
			return forgetErr
		}
		if hadWrap {
			convenienceState = "forgotten"
		}
	}
	payload := map[string]any{
		"vault_state":       "locked",
		"revoked_sessions":  revokedSessions,
		"revoked_grants":    revokedGrants,
		"convenience_state": convenienceState,
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(ctx, w, "Vault locked", "Revoked active sessions, grants, and the saved keychain unlock.",
			cliPair("Vault state", "locked"),
			cliPair("Revoked sessions", fmt.Sprintf("%d", revokedSessions)),
			cliPair("Revoked grants", fmt.Sprintf("%d", revokedGrants)),
			cliPair("Convenience unlock", convenienceState),
		)
	})
}

func vaultForgetDeviceCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return vaultForgetDeviceCommandWithDeps(ctx, args, stdout, defaultVaultGrantOpsDeps())
}

func vaultForgetDeviceCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, deps vaultGrantOpsDeps) error {
	fs := flag.NewFlagSet("vault forget-device", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp vault forget-device [--json]")
	}
	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	hadWrap, err := deps.DisableConvenienceUnlock(handle, ctx)
	if err != nil {
		return err
	}
	state := "already_forgotten"
	if hadWrap {
		state = "forgotten"
	}
	payload := map[string]any{
		"had_wrap":          hadWrap,
		"convenience_state": state,
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		summary := "The convenience-unlock keychain entry is already cleared."
		if hadWrap {
			summary = "Deleted the keychain entry and cleared the saved convenience-unlock wrap."
		}
		return renderSimpleAction(ctx, w, "Device forgotten", summary,
			cliPair("Convenience unlock", state),
			cliPair("Had saved wrap", fmt.Sprintf("%t", hadWrap)),
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
	case "list":
		return sessionListCommand(ctx, args[1:], stdout, s)
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
	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return fmt.Errorf("--project-root: %w", err)
	}
	*projectRoot = expandedRoot
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
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, safe, func(w io.Writer) error {
		return renderSessionOpenResult(w, safe.SessionID, safe.HostLabel, safe.ProjectRoot, safe.ExpiresAt.Format(secrettypes.TimeRFC3339))
	})
}

func sessionGrantPlaintextCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	return sessionGrantPlaintextCommandWithDeps(ctx, args, stdout, s, defaultSessionLocalDeps())
}

func sessionGrantPlaintextCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, s starter, deps sessionLocalDeps) error {
	fs := flag.NewFlagSet("session grant-plaintext", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	token := fs.String("token", strings.TrimSpace(os.Getenv(secrettypes.EnvSessionToken)), "")
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
	if err := deps.Approve(reply.Session, item.Name, plaintextAction); err != nil {
		return err
	}
	grant, err := deps.UseGrant(handle, *token, item.Name, plaintextAction, *window)
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
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(ctx, w, "Plaintext grant", "Granted one protected plaintext access path.",
			cliPair("Item", item.Name),
			cliPair("Action", string(plaintextAction)),
			cliPair("Scope", string(grant.Scope)),
			cliPair("Session", reply.Session.HostLabel),
		)
	})
}

func confirmPlaintextGrant(session runtime.SessionView, itemName string, action store.PlaintextAction) error {
	return confirmPlaintextGrantWithDeps(session, itemName, action, defaultConfirmPlaintextGrantDeps())
}

func confirmPlaintextGrantWithDeps(session runtime.SessionView, itemName string, action store.PlaintextAction, deps confirmPlaintextGrantDeps) error {
	if deps.UnderTest() {
		return nil
	}
	projectRoot := session.ProjectRoot
	if strings.TrimSpace(projectRoot) == "" {
		projectRoot = "(no project root)"
	}
	if deps.GOOS != "darwin" {
		file, ok := ttyutil.StdinFile(os.Stdin)
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
	cmd := deps.Command("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		return errors.New("plaintext grant approval was cancelled")
	}
	return nil
}

func sessionRevokeCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	return sessionRevokeCommandWithDeps(ctx, args, stdout, s, defaultVaultGrantOpsDeps())
}

func sessionRevokeCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, s starter, deps vaultGrantOpsDeps) error {
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
			if count, revokeErr := deps.RevokeAllGrants(handle); revokeErr != nil {
				return revokeErr
			} else {
				revokedGrants = count
			}
		}
		payload := map[string]any{"outcome": "revoked_all", "revoked_sessions": reply.RevokedCount, "revoked_grants": revokedGrants}
		return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
			return renderSimpleAction(ctx, w, "Sessions revoked", "Revoked all daemon-backed sessions.",
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
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(ctx, w, "Session revoked", "Revoked the daemon-backed session.",
			cliPair("Token", *token),
			cliPair("Outcome", "revoked"),
		)
	})
}

func sessionListCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	return sessionListCommandWithDeps(ctx, args, stdout, s, defaultSessionLocalDeps())
}

func sessionListCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, s starter, deps sessionLocalDeps) error {
	fs := flag.NewFlagSet("session list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	mineOnly := fs.Bool("mine", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp session list [--mine] [--json]")
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
	sessions := reply.Sessions
	if *mineOnly {
		me, err := deps.LocalUser()
		if err != nil {
			return err
		}
		filtered := sessions[:0:0]
		for _, sv := range sessions {
			if sv.LocalUser == me {
				filtered = append(filtered, sv)
			}
		}
		sessions = filtered
	}
	payload := map[string]any{"sessions": sessions}
	gf := globalFlagsFromContext(ctx)
	opts := ui.ColorOptions{
		Interactive: ui.IsInteractiveWriter(stdout),
		Disable:     gf.noColor,
		Quiet:       gf.quiet,
		Verbose:     gf.verbose,
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSessionListWithColor(w, sessions, opts)
	})
}

func renderSessionListWithColor(w io.Writer, sessions []runtime.SessionView, opts ui.ColorOptions) error {
	if len(sessions) == 0 {
		_, err := fmt.Fprintln(w, "No active sessions.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := "STATE\tID\tHOST\tPROJECT\tCONSUMER\tAGENT_SAFE\tLAST_SEEN\tEXPIRES"
	if opts.Verbose {
		header = "STATE\tID\tUSER\tHOST\tPROJECT\tCONSUMER\tAGENT_SAFE\tLAST_SEEN\tEXPIRES"
	}
	if _, err := fmt.Fprintln(tw, header); err != nil {
		return err
	}
	now := time.Now()
	for _, sv := range sessions {
		consumer := sv.ConsumerName
		if consumer == "" {
			consumer = "-"
		}
		badge := sessionStateBadge(sv, now, opts)
		var err error
		if opts.Verbose {
			user := sv.LocalUser
			if user == "" {
				user = "-"
			}
			_, err = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%t\t%s\t%s\n",
				badge, sv.ID, user, sv.HostLabel, sv.ProjectRoot, consumer, sv.AgentSafe,
				sv.LastSeenAt.Format(secrettypes.TimeRFC3339), sv.ExpiresAt.Format(secrettypes.TimeRFC3339),
			)
		} else {
			_, err = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%t\t%s\t%s\n",
				badge, sv.ID, sv.HostLabel, sv.ProjectRoot, consumer, sv.AgentSafe,
				sv.LastSeenAt.Format(secrettypes.TimeRFC3339), sv.ExpiresAt.Format(secrettypes.TimeRFC3339),
			)
		}
		if err != nil {
			return err
		}
	}
	return tw.Flush()
}

func sessionStateBadge(sv runtime.SessionView, now time.Time, opts ui.ColorOptions) string {
	if !sv.ExpiresAt.IsZero() && sv.ExpiresAt.After(now) {
		return ui.Colorize("[active]", ui.ColorOK, opts)
	}
	return ui.Colorize("[expired]", ui.ColorDeny, opts)
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
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, reply, func(w io.Writer) error {
		return renderSessionResolveResult(w, reply)
	})
}

func ensureClient(ctx context.Context, s starter) (*runtime.Client, error) {
	if err := s.EnsureDaemon(ctx); err != nil {
		return nil, err
	}
	return s.Connect(ctx)
}

// connectIfRunning attempts to connect to the daemon without starting it.
// It returns nil (not an error) when the daemon is not listening so callers
// can render a "not running" response rather than spawning a new process.
func connectIfRunning(ctx context.Context, s starter) *runtime.Client {
	client, err := s.Connect(ctx)
	if err != nil {
		return nil
	}
	return client
}

// renderNotRunning writes the canonical "daemon not running" response in either
// human or JSON form and exits cleanly (nil error = exit 0).
func renderNotRunning(stdout io.Writer, jsonOutput bool) error {
	if jsonOutput {
		return writeJSONResponse(stdout, map[string]any{"running": false})
	}
	_, err := fmt.Fprintln(stdout, "not running")
	return err
}

func openVaultHandle(ctx context.Context) (*store.Handle, error) {
	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return nil, err
	}
	password, err := loadMasterPassword()
	if err == nil {
		handle, perr := openStoreWithPasswordFn(ctx, vaultStore, password)
		if perr == nil && handle != nil {
			setAuditHMACKey(handle.AuditHMACKey())
		}
		return handle, perr
	}
	handle, unlockErr := vaultStore.OpenWithConvenienceUnlock(ctx)
	if unlockErr != nil && errors.Is(unlockErr, store.ErrKeyringUnavailable) {
		return nil, fmt.Errorf("HASP_MASTER_PASSWORD is not set and convenience unlock is unavailable")
	}
	if unlockErr == nil && handle != nil {
		setAuditHMACKey(handle.AuditHMACKey())
	}
	return handle, unlockErr
}
