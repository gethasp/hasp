package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	goruntime "runtime"

	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
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
	// Each Run() corresponds to a fresh CLI invocation in production. Drop
	// any process-level audit key cached from prior calls so a unit-test
	// process running back-to-back commands against different vaults can't
	// mis-sign an event under the wrong key (the SHA-256 fallback path
	// matches what a freshly-launched binary sees on the first call).
	clearAuditHMACKey()
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

	// Help short-circuits before the global flag parser so `hasp help <topic>`
	// keeps working even when a topic name collides with a flag-like token.
	switch args[0] {
	case "help":
		return printHelpTopic(stdout, args[1:])
	case "--help", "-h":
		return printHelpTopic(stdout, nil)
	}

	gf, rest, err := parseGlobalFlags(args)
	if err != nil {
		return err
	}
	ctx = contextWithGlobalFlags(ctx, gf)
	if gf.debug {
		// hasp-pjh4: route gf.debug to a stderr logger seam. Restore the
		// no-op default at the end of the dispatch so background goroutines
		// or test harnesses that survive past Run don't keep writing.
		prev := debugLogFn
		debugLogFn = func(format string, a ...any) {
			fmt.Fprintf(stderr, "hasp [debug] "+format+"\n", a...)
		}
		defer func() { debugLogFn = prev }()
	}

	if gf.version {
		return rewriteFlagDashForm(versionCommand(ctx, nil, stdout))
	}

	if len(rest) == 0 {
		printHelp(stdout)
		return nil
	}

	switch rest[0] {
	case "help":
		return printHelpTopic(stdout, rest[1:])
	case "--help", "-h":
		return printHelpTopic(stdout, nil)
	}

	spec, ok := lookupRootCommand(rest[0])
	if !ok {
		commands := rootCommandInventory()
		candidates := make([]string, 0, len(commands))
		for _, c := range commands {
			if !c.hidden {
				candidates = append(candidates, c.name)
			}
		}
		if hint, found := closestMatch(rest[0], candidates); found {
			return fmt.Errorf("unknown command %q; did you mean: %s?", rest[0], hint)
		}
		return fmt.Errorf("unknown command %q", rest[0])
	}
	// Global flags (--json, --yes, --no-color, --quiet, --verbose, --debug)
	// are stored in ctx via contextWithGlobalFlags and read by renderers via
	// globalFlagsFromContext. We no longer inject them into subcommand args to
	// avoid "flag provided but not defined" errors for commands that don't
	// declare a local copy of the flag (e.g. run, inject for --json).
	return dispatchRootCommand(ctx, spec, rest[1:], stdin, stdout, stderr, s)
}

func versionCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp version [--json]")
	}
	version := runtime.VersionString()
	payload := map[string]any{
		"version":        version,
		"commit":         runtime.CommitString(),
		"build_date":     runtime.BuildDateString(),
		"go_version":     goruntime.Version(),
		"format_version": store.FormatVersion(),
		"os":             goruntime.GOOS,
		"arch":           goruntime.GOARCH,
	}
	// KDF tuning details are diagnostic-only and useful for attacker
	// reconnaissance against weakened-build configurations. Gate them
	// behind --verbose; `hasp doctor` exposes the same data on demand.
	if globalFlagsFromContext(ctx).verbose {
		payload["default_kdf"] = store.DefaultKDFName()
		payload["default_kdf_iterations"] = store.DefaultKDFIterations()
		payload["default_kdf_time"] = store.DefaultKDFTime()
		payload["default_kdf_memory_kib"] = store.DefaultKDFMemoryKiB()
		payload["default_kdf_parallelism"] = store.DefaultKDFParallelism()
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		_, err := fmt.Fprintln(w, version)
		return err
	})
}
