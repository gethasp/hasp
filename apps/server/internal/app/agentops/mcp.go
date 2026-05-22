package agentops

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/store"
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
	if deps.AgentServeMCP == nil {
		return errors.New("agentops: AgentServeMCP not configured")
	}
	restores := []func(){}
	defer func() {
		restoreMCPEnv(restores)
	}()
	if err := setMCPEnv(deps, &restores, secrettypes.EnvAgentConsumer, name); err != nil {
		return deps.AgentServeMCP(ctx, stdin, stdout)
	}
	preflightCtx, cancelPreflight := agentMCPPreflightContext(ctx)
	defer cancelPreflight()
	if err := prepareAgentMCPEnv(preflightCtx, deps, name, &restores); err != nil {
		return deps.AgentServeMCP(ctx, stdin, stdout)
	}
	return deps.AgentServeMCP(ctx, stdin, stdout)
}

const defaultAgentMCPPreflightTimeout = 250 * time.Millisecond

var agentMCPPreflightTimeoutFn = agentMCPPreflightTimeout

func agentMCPPreflightContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := agentMCPPreflightTimeoutFn()
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

func agentMCPPreflightTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("HASP_AGENT_MCP_PREFLIGHT_TIMEOUT"))
	if raw == "" {
		return defaultAgentMCPPreflightTimeout
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return defaultAgentMCPPreflightTimeout
	}
	return parsed
}

func prepareAgentMCPEnv(ctx context.Context, deps Deps, name string, restores *[]func()) error {
	if deps.OpenVault == nil {
		return errors.New("agentops: OpenVault not configured")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	if deps.StoreGetAgent == nil {
		return errors.New("agentops: StoreGetAgent not configured")
	}
	consumer, err := deps.StoreGetAgent(handle, name)
	if errors.Is(err, store.ErrConsumerNotFound) {
		consumer = store.AgentConsumer{
			Name:        name,
			AgentID:     name,
			ProjectRoot: strings.TrimSpace(os.Getenv(secrettypes.EnvAgentProjectRoot)),
		}
		if deps.AgentConfigPaths != nil {
			if paths := deps.AgentConfigPaths(); paths != nil {
				consumer.ConfigPath = paths[name]
			}
		}
	} else if err != nil {
		return err
	}
	if strings.TrimSpace(consumer.ProjectRoot) == "" {
		consumer.ProjectRoot = strings.TrimSpace(os.Getenv(secrettypes.EnvAgentProjectRoot))
	}
	if strings.TrimSpace(consumer.ProjectRoot) == "" && deps.ResolveProjectRoot != nil {
		if cwd, werr := os.Getwd(); werr == nil {
			if root, inRepo, rerr := deps.ResolveProjectRoot(ctx, cwd); rerr == nil && inRepo {
				consumer.ProjectRoot = root
			}
		}
	}
	if err := setMCPEnv(deps, restores, secrettypes.EnvAgentConsumer, consumer.Name); err != nil {
		return err
	}
	if strings.TrimSpace(consumer.ProjectRoot) != "" {
		if err := setMCPEnv(deps, restores, secrettypes.EnvAgentProjectRoot, consumer.ProjectRoot); err != nil {
			return err
		}
	}
	if deps.AgentNewStarter == nil {
		return errors.New("agentops: AgentNewStarter not configured")
	}
	starter, err := deps.AgentNewStarter()
	if err != nil {
		return err
	}
	if deps.AgentBuildExecutionEnv == nil {
		return errors.New("agentops: AgentBuildExecutionEnv not configured")
	}
	env, err := deps.AgentBuildExecutionEnv(ctx, handle, consumer, starter, "agent:"+consumer.Name)
	if err != nil {
		return err
	}
	if token := envValue(env, secrettypes.EnvSessionToken); token != "" {
		if deps.AgentRegisterProcess == nil {
			return errors.New("agentops: AgentRegisterProcess not configured")
		}
		if err := deps.AgentRegisterProcess(ctx, starter, token, os.Getpid()); err != nil {
			return err
		}
	}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		restore, err := deps.SetEnv(key, value)
		if err != nil {
			return err
		}
		*restores = append(*restores, restore)
	}
	return nil
}

func setMCPEnv(deps Deps, restores *[]func(), key string, value string) error {
	if strings.TrimSpace(key) == "" {
		return nil
	}
	if deps.SetEnv != nil {
		restore, err := deps.SetEnv(key, value)
		if err != nil {
			return err
		}
		if restore != nil {
			*restores = append(*restores, restore)
		}
		return nil
	}
	old, hadOld := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		return err
	}
	*restores = append(*restores, func() {
		if hadOld {
			_ = os.Setenv(key, old)
			return
		}
		_ = os.Unsetenv(key)
	})
	return nil
}

func restoreMCPEnv(restores []func()) {
	for i := len(restores) - 1; i >= 0; i-- {
		restores[i]()
	}
}
