package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// proofCommand collapses the brokered first-proof flow into one command. It
// internally invokes `hasp run` with sensible defaults (--grant-project
// window, --grant-secret session, --grant-window 15m) and runs a tiny shell
// test that asserts the requested secret was injected into the brokered
// environment. The command prints PASS/FAIL on stdout and propagates the
// underlying run error so the shell exits non-zero on failure.
func proofCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, s starter) error {
	fs := flag.NewFlagSet("proof", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectRoot := fs.String("project-root", ".", "")
	secret := fs.String("secret", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*secret) == "" {
		return errors.New("usage: hasp proof --secret <name|alias> [--project-root <path>]")
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp proof --secret <name|alias> [--project-root <path>]")
	}
	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return fmt.Errorf("--project-root: %w", err)
	}
	*projectRoot = expandedRoot
	reference := strings.TrimSpace(*secret)

	runArgs := []string{
		"--project-root", *projectRoot,
		"--env", "HASP_SETUP_PROOF=" + reference,
		"--grant-project", "window",
		"--grant-secret", "session",
		"--grant-window", "15m",
		"--", "sh", "-c", `test -n "$HASP_SETUP_PROOF"`,
	}

	// Capture run output so it doesn't leak the redacted-but-still-noisy
	// shell stream into the user-facing PASS/FAIL summary. The shell test
	// command emits nothing on success, so dropping its stdout is safe.
	var runOut bytes.Buffer
	var runErr bytes.Buffer
	err = runCommand(ctx, runArgs, &runOut, &runErr, s)
	if err != nil {
		if !globalFlagsFromContext(ctx).json {
			fmt.Fprintf(stdout, "FAIL: %s — %v\n", *secret, err)
		}
		return err
	}
	return renderJSONOrHuman(ctx, stdout, false, map[string]any{
		"ok":             true,
		"secret":         *secret,
		"env":            "HASP_SETUP_PROOF",
		"audit_appended": true,
	}, func(w io.Writer) error {
		_, err := fmt.Fprintf(w, "PASS: brokered run injected %q as HASP_SETUP_PROOF; audit chain appended.\n", *secret)
		return err
	})
}
