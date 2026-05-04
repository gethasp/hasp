package sessionops

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var confirmPlaintextGrantReadString = func(r *bufio.Reader, delim byte) (string, error) {
	return r.ReadString(delim)
}

func sessionGrantPlaintext(ctx context.Context, deps Deps, args []string, stdout io.Writer, localDeps *LocalDeps) error {
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

	parsePlaintext := deps.ParsePlaintextAction
	if parsePlaintext == nil {
		return fmt.Errorf("sessionops: ParsePlaintextAction not wired")
	}
	parseScope := deps.ParseGrantScope
	if parseScope == nil {
		return fmt.Errorf("sessionops: ParseGrantScope not wired")
	}

	plaintextAction, err := parsePlaintext(*action)
	if err != nil {
		return err
	}
	if parseScope(*scope) != store.GrantOnce {
		return fmt.Errorf("plaintext grants only support --scope %q", store.GrantOnce)
	}

	if deps.NewStarter == nil {
		return fmt.Errorf("sessionops: NewStarter not wired")
	}
	s, err := deps.NewStarter()
	if err != nil {
		return err
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

	if deps.OpenVault == nil {
		return fmt.Errorf("sessionops: OpenVault not wired")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}

	if deps.GetItem == nil {
		return fmt.Errorf("sessionops: GetItem not wired")
	}
	item, err := deps.GetItem(handle, strings.TrimSpace(*itemName))
	if err != nil {
		return err
	}

	// Resolve local deps — caller may override via localDeps arg.
	var ld LocalDeps
	switch {
	case localDeps != nil:
		ld = *localDeps
	case deps.DefaultLocalDeps != nil:
		ld = deps.DefaultLocalDeps()
	default:
		ld = defaultLocalDepsFallback()
	}

	if err := ld.Approve(reply.Session, item.Name, plaintextAction); err != nil {
		return err
	}
	grant, err := ld.UseGrant(handle, *token, item.Name, plaintextAction, *window)
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
	if deps.RenderJSONOrHuman == nil {
		return fmt.Errorf("sessionops: RenderJSONOrHuman not wired")
	}
	if deps.RenderSimpleAction == nil {
		return fmt.Errorf("sessionops: RenderSimpleAction not wired")
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSimpleAction(ctx, w, "Plaintext grant", "Granted one protected plaintext access path.",
			cliPair("Item", item.Name),
			cliPair("Action", string(plaintextAction)),
			cliPair("Scope", string(grant.Scope)),
			cliPair("Session", reply.Session.HostLabel),
		)
	})
}

func sessionGrantMutation(ctx context.Context, deps Deps, args []string, stdout io.Writer, localDeps *LocalDeps) error {
	fs := flag.NewFlagSet("session grant-mutation", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	token := fs.String("token", strings.TrimSpace(os.Getenv(secrettypes.EnvSessionToken)), "")
	itemName := fs.String("item", "", "")
	action := fs.String("action", "", "")
	scope := fs.String("scope", string(store.GrantOnce), "")
	window := fs.Duration("grant-window", store.DefaultMutationGrantTTL, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" || strings.TrimSpace(*itemName) == "" || strings.TrimSpace(*action) == "" {
		return errors.New("usage: hasp session grant-mutation --token <token> --item <name> --action delete|expose|hide [--scope once] [--grant-window 60s]")
	}
	parseMutation := deps.ParseMutationAction
	if parseMutation == nil {
		return fmt.Errorf("sessionops: ParseMutationAction not wired")
	}
	parseScope := deps.ParseGrantScope
	if parseScope == nil {
		return fmt.Errorf("sessionops: ParseGrantScope not wired")
	}
	mutationAction, err := parseMutation(*action)
	if err != nil {
		return err
	}
	if parseScope(*scope) != store.GrantOnce {
		return fmt.Errorf("secret mutation grants only support --scope %q", store.GrantOnce)
	}
	if deps.NewStarter == nil {
		return fmt.Errorf("sessionops: NewStarter not wired")
	}
	s, err := deps.NewStarter()
	if err != nil {
		return err
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
		return errors.New("secret mutation grants require an agent-safe session")
	}
	if deps.OpenVault == nil {
		return fmt.Errorf("sessionops: OpenVault not wired")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	if deps.GetItem == nil {
		return fmt.Errorf("sessionops: GetItem not wired")
	}
	item, err := deps.GetItem(handle, strings.TrimSpace(*itemName))
	if err != nil {
		return err
	}
	if deps.ResolveBindingView == nil {
		return fmt.Errorf("sessionops: ResolveBindingView not wired")
	}
	binding, _, err := deps.ResolveBindingView(ctx, handle, reply.Session.ProjectRoot)
	if err != nil {
		return err
	}
	var ld LocalDeps
	switch {
	case localDeps != nil:
		ld = *localDeps
	case deps.DefaultLocalDeps != nil:
		ld = deps.DefaultLocalDeps()
	default:
		ld = defaultLocalDepsFallback()
	}
	if ld.ApproveMutation == nil {
		return fmt.Errorf("sessionops: LocalDeps.ApproveMutation not wired")
	}
	if ld.UseMutationGrant == nil {
		return fmt.Errorf("sessionops: LocalDeps.UseMutationGrant not wired")
	}
	if err := ld.ApproveMutation(reply.Session, item.Name, mutationAction); err != nil {
		return err
	}
	grant, err := ld.UseMutationGrant(handle, binding.ID, *token, item.Name, mutationAction, *window)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"session_id":         reply.Session.ID,
		"session_host_label": reply.Session.HostLabel,
		"project_root":       reply.Session.ProjectRoot,
		"binding_id":         binding.ID,
		"item_name":          item.Name,
		"mutation_action":    mutationAction,
		"scope":              grant.Scope,
		"expires_at":         grant.ExpiresAt,
	}
	if deps.RenderJSONOrHuman == nil {
		return fmt.Errorf("sessionops: RenderJSONOrHuman not wired")
	}
	if deps.RenderSimpleAction == nil {
		return fmt.Errorf("sessionops: RenderSimpleAction not wired")
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return deps.RenderSimpleAction(ctx, w, "Secret mutation grant", "Granted one protected mutation path.",
			cliPair("Item", item.Name),
			cliPair("Action", string(mutationAction)),
			cliPair("Scope", string(grant.Scope)),
			cliPair("Session", reply.Session.HostLabel),
		)
	})
}

// ConfirmPlaintextGrant is the exported approval prompt dispatcher. It calls
// ConfirmPlaintextGrantWithDeps using deps.DefaultConfirmPlaintextGrantDeps()
// or a built-in fallback.
func ConfirmPlaintextGrant(deps Deps, session runtime.SessionView, itemName string, action store.PlaintextAction) error {
	var cd ConfirmPlaintextGrantDeps
	if deps.DefaultConfirmPlaintextGrantDeps != nil {
		cd = deps.DefaultConfirmPlaintextGrantDeps()
	} else {
		cd = defaultConfirmPlaintextGrantDepsFallback()
	}
	return ConfirmPlaintextGrantWithDeps(session, itemName, action, cd)
}

// ConfirmPlaintextGrantWithDeps performs the operator approval prompt using
// the provided ConfirmPlaintextGrantDeps.
func ConfirmPlaintextGrantWithDeps(session runtime.SessionView, itemName string, action store.PlaintextAction, deps ConfirmPlaintextGrantDeps) error {
	if deps.UnderTest != nil && deps.UnderTest() {
		return nil
	}
	projectRoot := session.ProjectRoot
	if strings.TrimSpace(projectRoot) == "" {
		projectRoot = "(no project root)"
	}
	if deps.GOOS != "darwin" {
		f := os.Stdin
		if !ttyutil.IsCharDevice(f) {
			return errors.New("plaintext grants require local interactive operator approval")
		}
		phrase := fmt.Sprintf("grant %s %s", action, itemName)
		if _, err := fmt.Fprintf(os.Stdout, "Approve one-time %s of %s for %s\nProject: %s\nType %q to approve: ", action, itemName, session.HostLabel, projectRoot, phrase); err != nil {
			return err
		}
		answer, err := confirmPlaintextGrantReadString(bufio.NewReader(os.Stdin), '\n')
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
	if deps.Command == nil {
		return errors.New("sessionops: ConfirmPlaintextGrantDeps.Command not wired")
	}
	cmd := deps.Command("osascript", "-e", script)
	if err := cmd.Run(); err != nil {
		return errors.New("plaintext grant approval was cancelled")
	}
	return nil
}

// defaultLocalDepsFallback returns a LocalDeps that always returns errors
// because the seam vars are not wired. This is the last-resort fallback
// used when deps.DefaultLocalDeps is nil (e.g. in package-level contract tests
// that don't wire deps). The real wiring comes from defaultSessionDeps() in
// package app.
func defaultLocalDepsFallback() LocalDeps {
	return LocalDeps{
		Approve: func(_ runtime.SessionView, _ string, _ store.PlaintextAction) error {
			return errors.New("sessionops: LocalDeps.Approve not wired")
		},
		UseGrant: func(_ *store.Handle, _ string, _ string, _ store.PlaintextAction, _ time.Duration) (store.PlaintextGrant, error) {
			return store.PlaintextGrant{}, errors.New("sessionops: LocalDeps.UseGrant not wired")
		},
		ApproveMutation: func(_ runtime.SessionView, _ string, _ store.SecretMutationAction) error {
			return errors.New("sessionops: LocalDeps.ApproveMutation not wired")
		},
		UseMutationGrant: func(_ *store.Handle, _ string, _ string, _ string, _ store.SecretMutationAction, _ time.Duration) (store.MutationGrant, error) {
			return store.MutationGrant{}, errors.New("sessionops: LocalDeps.UseMutationGrant not wired")
		},
		LocalUser: func() (string, error) {
			return "", errors.New("sessionops: LocalDeps.LocalUser not wired")
		},
	}
}

// defaultConfirmPlaintextGrantDepsFallback returns a ConfirmPlaintextGrantDeps
// that is safe for use when the real wiring is unavailable.
func defaultConfirmPlaintextGrantDepsFallback() ConfirmPlaintextGrantDeps {
	return ConfirmPlaintextGrantDeps{
		GOOS:      "linux",
		Command:   nil,
		UnderTest: func() bool { return true },
	}
}
