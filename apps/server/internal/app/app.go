package app

import (
	"context"
	"fmt"
	"io"

	"github.com/gethasp/hasp/apps/server/internal/mcp"
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
	case "version":
		_, err := fmt.Fprintln(stdout, runtime.Version())
		return err
	case "init":
		return initCommand(ctx, stdout)
	case "setup":
		return setupCommand(ctx, args[1:], stdin, stdout, stderr)
	case "bootstrap":
		return bootstrapCommandWithInput(ctx, args[1:], stdin, stdout, bootstrapVerification)
	case "import":
		return importCommandWithInput(ctx, args[1:], stdin, stdout)
	case "project":
		return projectCommand(ctx, args[1:], stdout)
	case "set":
		return setCommand(ctx, args[1:], stdout)
	case "capture":
		return captureCommand(ctx, args[1:], stdout, s)
	case "redact":
		return redactCommand(ctx, stdin, stdout)
	case "audit":
		return auditCommand(stdout)
	case "daemon":
		return daemonCommand(ctx, args[1:], stdout, s)
	case "ping":
		return pingCommand(ctx, stdout, s)
	case "status":
		return statusCommand(ctx, stdout, s)
	case "session":
		return sessionCommand(ctx, args[1:], stdout, s)
	case "run":
		return runCommand(ctx, args[1:], stdout, stderr, s)
	case "inject":
		return injectCommand(ctx, args[1:], stdout, stderr, s)
	case "write-env":
		return writeEnvCommand(ctx, args[1:], stdout, stderr, s)
	case "check-repo":
		return checkRepoCommand(ctx, args[1:], stdout)
	case "export-backup":
		return exportBackupCommand(ctx, args[1:], stdout)
	case "restore-backup":
		return restoreBackupCommand(ctx, args[1:], stdout)
	case "mcp":
		return mcp.Serve(ctx, stdin, stdout)
	case "tui":
		return tuiCommand(ctx, args[1:], stdout)
	case "help", "--help", "-h":
		printHelp(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printHelp(w io.Writer) {
	fmt.Fprintln(w, "hasp commands:")
	fmt.Fprintln(w, "  version")
	fmt.Fprintln(w, "  init")
	fmt.Fprintln(w, "  setup [--non-interactive ...]")
	fmt.Fprintln(w, "  bootstrap --profile <id> [--import <path|->] [--bind-imports] | bootstrap generic | bootstrap profiles | bootstrap doctor --profile <id>|generic")
	fmt.Fprintln(w, "  import [--project-root <path>] [--bind] [--name <name>] [--preview] [--format auto|env|json] <path|->")
	fmt.Fprintln(w, "  project adopt|bind|status|unbind")
	fmt.Fprintln(w, "  daemon serve|start|stop|status")
	fmt.Fprintln(w, "  ping")
	fmt.Fprintln(w, "  status")
	fmt.Fprintln(w, "  session open --host-label <label> --project-root <path>")
	fmt.Fprintln(w, "  session resolve --token <token>")
	fmt.Fprintln(w, "  session revoke --token <token>")
	fmt.Fprintln(w, "  setup | bootstrap | init | import | set | run | inject | write-env | audit | check-repo | export-backup | restore-backup | mcp | tui")
}
