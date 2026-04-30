package runtimeops

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

var (
	managerRunDaemon   = (*runtime.Manager).RunDaemon
	managerStartDaemon = (*runtime.Manager).StartDaemon
	managerStopDaemon  = (*runtime.Manager).StopDaemon
)

func daemonHandler(ctx context.Context, deps Deps, args []string, stdout io.Writer, _ io.Writer) error {
	isHelp := deps.IsHelpArg
	if isHelp == nil {
		isHelp = isHelpArgFallback
	}
	printHelp := deps.PrintHelpTopic
	if printHelp == nil {
		printHelp = func(w io.Writer, _ []string) error {
			_, err := fmt.Fprintln(w, "Usage: hasp daemon <subcommand>\n\nSubcommands: serve, start, stop, status")
			return err
		}
	}

	if len(args) == 0 || isHelp(args[0]) {
		return printHelp(stdout, []string{"daemon"})
	}

	newManager := deps.NewRuntimeManager
	if newManager == nil {
		newManager = runtime.NewManager
	}

	// Construct a manager upfront for all subcommands, matching the original
	// daemonCommand behaviour where manager construction failure is surfaced
	// before any subcommand-specific work (including delegating to status).
	manager, err := newManager()
	if err != nil {
		return err
	}

	switch args[0] {
	case "serve":
		return managerRunDaemon(manager, ctx)
	case "start":
		return managerStartDaemon(manager, ctx)
	case "stop":
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
	case "status":
		return statusHandler(ctx, deps, args[1:], stdout)
	default:
		return fmt.Errorf("unknown daemon subcommand %q", args[0])
	}
}
