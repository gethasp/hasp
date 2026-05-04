package agentops

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
)

func agentMCPHandler(ctx context.Context, deps Deps, args []string, stdin io.Reader, stdout io.Writer) error {
	name, remaining := consumerNameAndArgs(args)
	fs := newFlagSet(deps, "agent mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(remaining); err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		return errors.New("usage: hasp agent mcp <agent-id>")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	consumer, err := deps.StoreGetAgent(handle, name)
	if err != nil {
		return err
	}
	starter, err := deps.AgentNewStarter()
	if err != nil {
		return err
	}
	env, err := deps.AgentBuildExecutionEnv(ctx, handle, consumer, starter, "agent:"+consumer.Name)
	if err != nil {
		return err
	}
	if token := envValue(env, secrettypes.EnvSessionToken); token != "" {
		if err := deps.AgentRegisterProcess(ctx, starter, token, os.Getpid()); err != nil {
			return err
		}
	}
	restores := make([]func(), 0, len(env))
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		restore, err := deps.SetEnv(key, value)
		if err != nil {
			return err
		}
		restores = append(restores, restore)
	}
	defer func() {
		for i := len(restores) - 1; i >= 0; i-- {
			restores[i]()
		}
	}()
	return deps.AgentServeMCP(ctx, stdin, stdout)
}
