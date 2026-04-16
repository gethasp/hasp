package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var appCanonicalProjectRootFn = store.CanonicalProjectRoot
var openVaultHandleFn = openVaultHandle

func exportBackupCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("export-backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
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
	return json.NewEncoder(stdout).Encode(map[string]any{"output_path": *outputPath, "checkpoint": checkpoint})
}

func restoreBackupCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("restore-backup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
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
	return json.NewEncoder(stdout).Encode(map[string]any{"input_path": *inputPath, "checkpoint": checkpoint})
}

func tuiCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
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
	manager, err := runtime.NewManager()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return errors.New("usage: hasp daemon <serve|start|stop|status>")
	}
	switch args[0] {
	case "serve":
		return manager.RunDaemon(ctx)
	case "start":
		return manager.StartDaemon(ctx)
	case "stop":
		return manager.StopDaemon()
	case "status":
		return statusCommand(ctx, stdout, s)
	default:
		return fmt.Errorf("unknown daemon subcommand %q", args[0])
	}
}

func pingCommand(ctx context.Context, stdout io.Writer, s starter) error {
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()

	reply, err := client.Ping(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(reply)
}

func statusCommand(ctx context.Context, stdout io.Writer, s starter) error {
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()

	reply, err := client.Status(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "socket\t%s\n", reply.SocketPath)
	fmt.Fprintf(tw, "pid\t%d\n", reply.PID)
	fmt.Fprintf(tw, "started_at\t%s\n", reply.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(tw, "active_sessions\t%d\n", reply.ActiveSessions)
	return tw.Flush()
}

func sessionCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	if len(args) == 0 {
		return errors.New("usage: hasp session <open|revoke>")
	}
	switch args[0] {
	case "open":
		return sessionOpenCommand(ctx, args[1:], stdout, s)
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
	hostLabel := fs.String("host-label", "generic-client", "")
	projectRoot := fs.String("project-root", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	canonicalRoot, err := appCanonicalProjectRootFn(ctx, *projectRoot)
	if err != nil {
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
	return json.NewEncoder(stdout).Encode(safe)
}

func sessionRevokeCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("session revoke", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	token := fs.String("token", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		return errors.New("usage: hasp session revoke --token <token>")
	}
	client, err := ensureClient(ctx, s)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.RevokeSession(ctx, *token); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "revoked")
	return err
}

func sessionResolveCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	fs := flag.NewFlagSet("session resolve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
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
	return json.NewEncoder(stdout).Encode(reply)
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
	return vaultStore.OpenWithConvenienceUnlock(ctx)
}
