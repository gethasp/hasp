package agentops

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestAgentLaunchUsesCurrentRepositoryForRootlessConsumer(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	t.Setenv(secrettypes.EnvAgentProjectRoot, "")
	for _, missing := range []bool{false, true} {
		deps := fullAgentDeps(t)
		deps.StoreGetAgent = func(_ *store.Handle, name string) (store.AgentConsumer, error) {
			if missing {
				return store.AgentConsumer{}, store.ErrConsumerNotFound
			}
			return store.AgentConsumer{Name: name, AgentID: name}, nil
		}
		deps.ResolveProjectRoot = func(_ context.Context, cwd string) (string, bool, error) {
			if cwd != root {
				t.Fatalf("resolved %q instead of current directory %q", cwd, root)
			}
			return root, true, nil
		}
		deps.AgentBuildExecutionEnv = func(_ context.Context, _ *store.Handle, consumer store.AgentConsumer, _ Starter, _ string) ([]string, error) {
			if consumer.ProjectRoot != root {
				t.Fatalf("session root %q, want %q", consumer.ProjectRoot, root)
			}
			return []string{secrettypes.EnvAgentProjectRoot + "=" + root}, nil
		}
		var output bytes.Buffer
		if err := AgentCommand(context.Background(), deps, []string{"launch", "pi", "--", "sh", "-c", "pwd"}, strings.NewReader(""), &output, io.Discard); err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(output.String()) != root {
			t.Fatalf("child cwd %q, want %q", output.String(), root)
		}
	}
	if cwd, _ := os.Getwd(); cwd != root {
		t.Fatal("launch changed the parent's working directory")
	}
}
