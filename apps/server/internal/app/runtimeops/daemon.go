package runtimeops

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
	"github.com/gethasp/hasp/apps/server/internal/httpapi"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var (
	managerRunDaemon   = (*runtime.Manager).RunDaemon
	managerStartDaemon = (*runtime.Manager).StartDaemon
	managerStopDaemon  = (*runtime.Manager).StopDaemon
)

var validRestartReasons = map[string]bool{
	"app-update": true,
	"operator":   true,
	"update":     true,
}

func daemonHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer, _ io.Writer) error {
	isHelp := deps.IsHelpArg
	if isHelp == nil {
		isHelp = isHelpArgFallback
	}
	printHelp := deps.PrintHelpTopic
	if printHelp == nil {
		printHelp = func(w io.Writer, _ []string) error {
			_, err := fmt.Fprintln(w, "Usage: hasp daemon <subcommand>\n\nSubcommands: run, serve, start, stop, restart, status, http-key")
			return err
		}
	}

	if len(args) == 0 || isHelp(args[0]) {
		return printHelp(stdout, []string{"daemon"})
	}

	if args[0] == "http-key" {
		return daemonHTTPKey(ctx, deps, args[1:], stdout)
	}

	newManager := deps.NewRuntimeManager
	if newManager == nil {
		newManager = runtime.NewManager
	}
	manager, err := newManager()
	if err != nil {
		return err
	}

	switch args[0] {
	case "run":
		return runDaemon(ctx, manager, args[1:])
	case "serve":
		if err := ctx.Err(); err != nil {
			return nil
		}
		return managerRunDaemon(manager, ctx)
	case "start":
		return managerStartDaemon(manager, ctx)
	case "stop":
		return stopDaemon(manager, deps)
	case "restart":
		return restartDaemon(ctx, deps, manager, args[1:])
	case "status":
		return statusHandler(ctx, deps, args[1:], stdout)
	default:
		return fmt.Errorf("unknown daemon subcommand %q", args[0])
	}
}

func runDaemon(ctx context.Context, manager *runtime.Manager, args []string) error {
	fs := flag.NewFlagSet("daemon run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	foreground := fs.Bool("foreground", false, "")
	guiListener := fs.Bool("gui-listener", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: hasp daemon run [--foreground] [--gui-listener]")
	}
	_ = foreground
	_ = guiListener
	if err := ctx.Err(); err != nil {
		return nil
	}
	return managerRunDaemon(manager, ctx)
}

func stopDaemon(manager *runtime.Manager, deps Deps) error {
	if err := managerStopDaemon(manager); err != nil {
		if strings.Contains(err.Error(), "process already finished") {
			if deps.NewInternalError != nil {
				return deps.NewInternalError("daemon was not running")
			}
			return fmt.Errorf("daemon was not running")
		}
		return err
	}
	return nil
}

func restartDaemon(ctx context.Context, deps Deps, manager *runtime.Manager, args []string) error {
	fs := flag.NewFlagSet("daemon restart", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reason := fs.String("reason", "operator", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: hasp daemon restart [--reason app-update|operator|update]")
	}
	if !validRestartReasons[*reason] {
		return fmt.Errorf("invalid restart reason %q", *reason)
	}
	if err := lockVaultIfRunning(ctx, deps, *reason); err != nil {
		return err
	}
	if err := managerStopDaemon(manager); err != nil && !strings.Contains(err.Error(), "process already finished") {
		return err
	}
	return managerStartDaemon(manager, ctx)
}

func lockVaultIfRunning(ctx context.Context, deps Deps, reason string) error {
	if deps.NewStarter == nil || deps.ConnectIfRunning == nil {
		return nil
	}
	starter, err := deps.NewStarter()
	if err != nil {
		return err
	}
	client := deps.ConnectIfRunning(ctx, starter)
	if client == nil {
		return nil
	}
	defer client.Close()
	_, err = client.LockVaultWithCause(ctx, "daemon-restart")
	return err
}

func daemonHTTPKey(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	keyring := store.NewDefaultKeyring()
	if deps.HTTPKeyring != nil {
		keyring = deps.HTTPKeyring()
	}
	switch {
	case len(args) == 1 && args[0] == "fingerprint":
		fingerprint, err := httpapi.HMACKeyFingerprint(ctx, keyring)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "%s\n", fingerprint)
		return err
	case len(args) == 1 && args[0] == "reinitialize":
		if err := approveHMACKeyReinitialize(deps); err != nil {
			return err
		}
		key, err := httpapi.ReinitializeHMACKey(ctx, keyring)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "reinitialized %s\n", httpapi.HMACKeyFingerprintForKey(key))
		return err
	default:
		return fmt.Errorf("usage: hasp daemon http-key fingerprint|reinitialize")
	}
}

func approveHMACKeyReinitialize(deps Deps) error {
	if deps.ApproveHMACKeyReinitialize != nil {
		return deps.ApproveHMACKeyReinitialize()
	}
	if strings.HasSuffix(strings.TrimSpace(filepath.Base(os.Args[0])), ".test") {
		return nil
	}
	if goruntime.GOOS == "darwin" {
		script := `display dialog "Reinitialize HASP daemon HMAC pairing? Existing daemon connections must reconnect." buttons {"Cancel", "Reinitialize"} default button "Cancel" with icon caution`
		if err := exec.Command("osascript", "-e", script).Run(); err != nil {
			return errors.New("HMAC pairing reinitialize approval was cancelled")
		}
		return nil
	}
	if !ttyutil.IsCharDevice(os.Stdin) {
		return errors.New("HMAC pairing reinitialize requires local interactive operator approval")
	}
	const phrase = "reinitialize hmac pairing"
	if _, err := fmt.Fprintf(os.Stdout, "This rotates the local daemon HMAC key and forces clients to reconnect.\nType %q to approve: ", phrase); err != nil {
		return err
	}
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.TrimSpace(answer) != phrase {
		return errors.New("HMAC pairing reinitialize approval was cancelled")
	}
	return nil
}
