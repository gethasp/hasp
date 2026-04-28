package app

import (
	"bufio"
	"context"
	"errors"
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
	"github.com/gethasp/hasp/apps/server/internal/app/sessionops"
	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/app/vaultops"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// sessionLocalDeps bundles the seams that personalise session-related
// CLI commands: the plaintext-grant approval prompt (Approve), the
// store-side grant issuance (UseGrant) and the local-user lookup that
// "session list --mine" filters on. Tests construct a local instance
// to inject deterministic outcomes without touching package-level vars.
type sessionLocalDeps struct {
	Approve   func(session runtime.SessionView, itemName string, action store.PlaintextAction) error
	UseGrant  func(handle *store.Handle, token string, itemName string, action store.PlaintextAction, window time.Duration) (store.PlaintextGrant, error)
	LocalUser func() (string, error)
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

// ── Session command shims ─────────────────────────────────────────────────────
//
// These shims preserve the package-app function signatures that existing tests
// call directly. Each one delegates to sessionops.SessionCommand via
// defaultSessionDeps() (or a locally-customised Deps). Zero behaviour change.

func sessionCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	deps := defaultSessionDeps()
	if s != nil {
		deps.NewStarter = func() (sessionops.Starter, error) { return s, nil }
	}
	return sessionops.SessionCommand(ctx, deps, args, nil, stdout, io.Discard)
}

func sessionOpenCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	deps := defaultSessionDeps()
	if s != nil {
		deps.NewStarter = func() (sessionops.Starter, error) { return s, nil }
	}
	return sessionops.SessionCommand(ctx, deps, append([]string{"open"}, args...), nil, stdout, io.Discard)
}

func sessionGrantPlaintextCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	deps := defaultSessionDeps()
	if s != nil {
		deps.NewStarter = func() (sessionops.Starter, error) { return s, nil }
	}
	return sessionops.SessionCommand(ctx, deps, append([]string{"grant-plaintext"}, args...), nil, stdout, io.Discard)
}

func sessionGrantPlaintextCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, s starter, ld sessionLocalDeps) error {
	deps := defaultSessionDeps()
	if s != nil {
		deps.NewStarter = func() (sessionops.Starter, error) { return s, nil }
	}
	deps.DefaultLocalDeps = func() sessionops.LocalDeps {
		return sessionops.LocalDeps{
			Approve:   ld.Approve,
			UseGrant:  ld.UseGrant,
			LocalUser: ld.LocalUser,
		}
	}
	return sessionops.SessionCommand(ctx, deps, append([]string{"grant-plaintext"}, args...), nil, stdout, io.Discard)
}

func sessionRevokeCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	deps := defaultSessionDeps()
	if s != nil {
		deps.NewStarter = func() (sessionops.Starter, error) { return s, nil }
	}
	return sessionops.SessionCommand(ctx, deps, append([]string{"revoke"}, args...), nil, stdout, io.Discard)
}

func sessionRevokeCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, s starter, grantDeps vaultGrantOpsDeps) error {
	deps := defaultSessionDeps()
	if s != nil {
		deps.NewStarter = func() (sessionops.Starter, error) { return s, nil }
	}
	deps.GrantOps = func() vaultops.GrantOpsDeps {
		return vaultops.GrantOpsDeps{
			RevokeAllGrants:          grantDeps.RevokeAllGrants,
			DisableConvenienceUnlock: grantDeps.DisableConvenienceUnlock,
		}
	}
	return sessionops.SessionCommand(ctx, deps, append([]string{"revoke"}, args...), nil, stdout, io.Discard)
}

func sessionResolveCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	deps := defaultSessionDeps()
	if s != nil {
		deps.NewStarter = func() (sessionops.Starter, error) { return s, nil }
	}
	return sessionops.SessionCommand(ctx, deps, append([]string{"resolve"}, args...), nil, stdout, io.Discard)
}

// renderSessionListWithColor writes sessions as a colourised tabular listing.
// It is kept in package app because existing tests (session_list_color_red_test.go,
// verbose_renderer_red_test.go) call it directly by name.
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

// sessionStateBadge returns a colourised "[active]" or "[expired]" badge for
// a session view. Called by renderSessionListWithColor.
func sessionStateBadge(sv runtime.SessionView, now time.Time, opts ui.ColorOptions) string {
	if !sv.ExpiresAt.IsZero() && sv.ExpiresAt.After(now) {
		return ui.Colorize("[active]", ui.ColorOK, opts)
	}
	return ui.Colorize("[expired]", ui.ColorDeny, opts)
}
