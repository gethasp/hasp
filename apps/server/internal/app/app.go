package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

type starter interface {
	EnsureDaemon(context.Context) error
	Connect(context.Context) (*runtime.Client, error)
}

type runtimeStarter struct {
	manager *runtime.Manager
}

var newRuntimeStarterFn = newRuntimeStarter

func newRuntimeStarter() (*runtimeStarter, error) {
	manager, err := runtime.NewManager()
	if err != nil {
		return nil, err
	}
	return &runtimeStarter{manager: manager}, nil
}

func (s *runtimeStarter) EnsureDaemon(ctx context.Context) error {
	return s.manager.EnsureDaemon(ctx)
}

func (s *runtimeStarter) Connect(ctx context.Context) (*runtime.Client, error) {
	return runtime.Dial(ctx, s.manager.SocketPath())
}

func Run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	starter, err := newRuntimeStarterFn()
	if err != nil {
		return err
	}
	return runWithStarter(ctx, args, stdin, stdout, stderr, starter)
}

func runWithStarter(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, s starter) error {
	if len(args) == 0 {
		printHelp(stdout)
		return nil
	}

	switch args[0] {
	case "help":
		return printHelpTopic(stdout, args[1:])
	case "--help", "-h":
		return printHelpTopic(stdout, nil)
	case "bootstrap":
		if len(args) > 1 && isHelpArg(args[1]) {
			return printHelpTopic(stdout, []string{"bootstrap"})
		}
		return bootstrapCommandWithInput(ctx, args[1:], stdin, stdout, bootstrapVerification)
	case "redact":
		return redactCommand(ctx, stdin, stdout)
	}
	spec, ok := lookupRootCommand(args[0])
	if !ok {
		return fmt.Errorf("unknown command %q", args[0])
	}
	return dispatchRootCommand(ctx, spec, args[1:], stdin, stdout, stderr, s)
}

func versionCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp version [--json]")
	}
	version := runtime.Version()
	payload := map[string]any{"version": version}
	return renderJSONOrHuman(stdout, *jsonOutput, payload, func(w io.Writer) error {
		_, err := fmt.Fprintln(w, version)
		return err
	})
}
