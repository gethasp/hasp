package agentops

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/store"

	goexec "os/exec"
)

func agentLaunchHandler(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, shellMode bool) error {
	name, remaining := consumerNameAndArgs(args)
	commandName := "agent launch"
	usage := "usage: hasp agent launch <agent-id> -- <command...>"
	if shellMode {
		commandName = "agent shell"
		usage = "usage: hasp agent shell <agent-id> [shell args...]"
	}
	fs := newFlagSet(deps, commandName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" {
		return errors.New(usage)
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	consumer, err := deps.StoreGetAgent(handle, name)
	if errors.Is(err, store.ErrConsumerNotFound) {
		consumer = store.AgentConsumer{
			Name:        name,
			AgentID:     name,
			ProjectRoot: strings.TrimSpace(os.Getenv(secrettypes.EnvAgentProjectRoot)),
		}
	} else if err != nil {
		return err
	}
	starter, err := deps.AgentNewStarter()
	if err != nil {
		return err
	}
	command := fs.Args()
	if shellMode {
		shell := strings.TrimSpace(deps.AgentUserShell())
		if shell == "" {
			shell = "/bin/sh"
		}
		command = append([]string{shell, "-l"}, command...)
	} else if len(command) == 0 {
		return errors.New(usage)
	}
	env, err := deps.AgentBuildExecutionEnv(ctx, handle, consumer, starter, "agent:"+consumer.Name)
	if err != nil {
		return err
	}
	cmd := deps.AgentExecCommandContext(ctx, command[0], command[1:]...)
	if consumer.ProjectRoot != "" {
		cmd.Dir = consumer.ProjectRoot
	}
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	if token := envValue(env, secrettypes.EnvSessionToken); token != "" {
		if err := deps.AgentRegisterProcess(ctx, starter, token, cmd.Process.Pid); err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return err
		}
	}
	if err := cmd.Wait(); err != nil {
		var exitErr *goexec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("command exited with code %d", exitErr.ExitCode())
		}
		return err
	}
	if deps.AppendAudit != nil {
		deps.AppendAudit(audit.EventRun, "user", map[string]any{
			"action":        "consumer.agent.launch",
			"consumer_type": "agent",
			"consumer_name": consumer.Name,
			"project_root":  consumer.ProjectRoot,
			"command":       command,
			"shell_mode":    shellMode,
			"outcome":       "completed",
		})
	}
	return nil
}
