package agentops

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/cmddispatch"
	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type fakeAgentStarter struct{}

func (fakeAgentStarter) EnsureDaemon(context.Context) error { return nil }
func (fakeAgentStarter) Connect(context.Context) (*runtime.Client, error) {
	return nil, nil
}

func fullAgentDeps(t *testing.T) Deps {
	t.Helper()
	var envSet []string
	return Deps{
		OpenVault: func(context.Context) (*store.Handle, error) { return &store.Handle{}, nil },
		StoreGetAgent: func(_ *store.Handle, name string) (store.AgentConsumer, error) {
			return store.AgentConsumer{Name: name, AgentID: name, ProjectRoot: t.TempDir(), ConfigPath: "/tmp/" + name + ".json"}, nil
		},
		StoreListAgents: func(*store.Handle) []store.AgentConsumer {
			return []store.AgentConsumer{{Name: "codex", AgentID: "codex-cli"}}
		},
		StoreUpsertAgent: func(_ *store.Handle, consumer store.AgentConsumer) (store.AgentConsumer, error) {
			return consumer, nil
		},
		StoreDeleteAgent:          func(*store.Handle, string) error { return nil },
		RemoveAgentConsumerConfig: func(string, string) error { return nil },
		AgentUserShell:            func() string { return "sh" },
		AgentExecCommandContext:   exec.CommandContext,
		AgentNewStarter:           func() (Starter, error) { return fakeAgentStarter{}, nil },
		AgentBuildExecutionEnv: func(context.Context, *store.Handle, store.AgentConsumer, Starter, string) ([]string, error) {
			return []string{secrettypes.EnvSessionToken + "=token", "HASP_EXTRA=value", "BROKEN"}, nil
		},
		AgentRegisterProcess: func(context.Context, Starter, string, int) error { return nil },
		AgentServeMCP: func(_ context.Context, stdin io.Reader, stdout io.Writer) error {
			_, err := io.Copy(stdout, stdin)
			return err
		},
		AgentLoadSupportStatuses: func() ([]profiles.SupportStatus, error) {
			return []profiles.SupportStatus{{
				Profile:            profiles.Profile{ID: "codex-cli", Name: "Codex CLI", Command: []string{"codex"}, DocsPath: "docs.md"},
				SupportTier:        profiles.SupportTierFirstClassShipped,
				CompatibilityLabel: profiles.CompatibilityLabelFirstClass,
				FirstClass:         true,
				Proof: map[string]profiles.SupportCheck{
					"evals":      {Status: "pass"},
					"benchmarks": {Status: "pass"},
				},
			}}, nil
		},
		SetEnv: func(key string, value string) (func(), error) {
			envSet = append(envSet, key+"="+value)
			return func() { envSet = append(envSet, "restore:"+key) }, nil
		},
		ExpandUserPath: func(path string) (string, error) { return strings.Replace(path, "~", "/home/test", 1), nil },
		ResolvePaths:   func() (string, error) { return t.TempDir(), nil },
		ResolveProjectRoot: func(_ context.Context, root string) (string, bool, error) {
			return "/repo/" + strings.TrimPrefix(root, "/home/test/"), true, nil
		},
		EnsureProjectBinding: func(context.Context, *store.Handle, string) error { return nil },
		WriteAgentConfig: func(agentID string, homeDir string) (AgentSetupOutcome, error) {
			return AgentSetupOutcome{ID: agentID, Label: agentID, ConfigPath: homeDir + "/" + agentID + ".json", Changed: true}, nil
		},
		AgentConfigPaths: func() map[string]string { return map[string]string{"codex-cli": "/tmp/codex.toml"} },
		GenericAgentView: func() AgentSupportedProfileView {
			return AgentSupportedProfileView{ID: "generic", Name: "Generic", ConnectCommand: []string{"hasp", "agent"}}
		},
		AppendAudit: func(string, string, map[string]any) {},
		RenderJSONOrHuman: func(_ context.Context, stdout io.Writer, _ bool, _ any, human func(io.Writer) error) error {
			return human(stdout)
		},
		RenderConnectResult: func(out io.Writer, consumer store.AgentConsumer, outcome AgentSetupOutcome) error {
			_, err := out.Write([]byte(consumer.Name + ":" + outcome.ConfigPath))
			return err
		},
		RenderConsumerList: func(out io.Writer, consumers []store.AgentConsumer) error {
			_, err := out.Write([]byte(consumers[0].Name))
			return err
		},
		RenderSimpleAction: func(_ context.Context, out io.Writer, title string, lead string, pairs ...[2]string) error {
			_, err := out.Write([]byte(title + ":" + pairs[0][1]))
			return err
		},
		NewFlagSet: flag.NewFlagSet,
	}
}

func TestAgentHandlersSuccessPaths(t *testing.T) {
	deps := fullAgentDeps(t)
	ctx := context.Background()
	var out bytes.Buffer

	if err := AgentCommand(ctx, deps, []string{"connect", "codex", "--project-root", "~/repo"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !strings.Contains(out.String(), "codex:") {
		t.Fatalf("connect output %q", out.String())
	}
	out.Reset()
	if err := AgentCommand(ctx, deps, []string{"disconnect", "codex"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if !strings.Contains(out.String(), "Agent disconnected") {
		t.Fatalf("disconnect output %q", out.String())
	}
	out.Reset()
	if err := AgentCommand(ctx, deps, []string{"list"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("list: %v", err)
	}
	if out.String() != "codex" {
		t.Fatalf("list output %q", out.String())
	}
	out.Reset()
	if err := AgentCommand(ctx, deps, []string{"list-supported"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("list-supported: %v", err)
	}
	if !strings.Contains(out.String(), "codex-cli") || !strings.Contains(out.String(), "generic") {
		t.Fatalf("list-supported output %q", out.String())
	}
	out.Reset()
	if err := AgentCommand(ctx, deps, []string{"mcp", "codex"}, strings.NewReader("mcp"), &out, io.Discard); err != nil {
		t.Fatalf("mcp: %v", err)
	}
	if out.String() != "mcp" {
		t.Fatalf("mcp output %q", out.String())
	}
	out.Reset()
	if err := AgentCommand(ctx, deps, []string{"launch", "codex", "--", "sh", "-c", "exit 0"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("launch: %v", err)
	}
	if err := AgentCommand(ctx, deps, []string{"shell", "codex"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("shell: %v", err)
	}
}

func TestAgentHandlersErrorBranches(t *testing.T) {
	deps := fullAgentDeps(t)
	ctx := context.Background()
	cases := []struct {
		name string
		args []string
	}{
		{"connect usage", []string{"connect"}},
		{"disconnect usage", []string{"disconnect"}},
		{"mcp usage", []string{"mcp"}},
		{"launch usage", []string{"launch", "codex"}},
		{"list-supported usage", []string{"list-supported", "extra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := AgentCommand(ctx, deps, tc.args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
				t.Fatal("expected error")
			}
		})
	}

	deps.ExpandUserPath = func(string) (string, error) { return "", errors.New("expand") }
	if err := AgentCommand(ctx, deps, []string{"connect", "codex", "--project-root", "~"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected expand error")
	}
	deps = fullAgentDeps(t)
	deps.StoreGetAgent = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{}, errors.New("get")
	}
	if err := AgentCommand(ctx, deps, []string{"disconnect", "codex"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected get error")
	}
	deps = fullAgentDeps(t)
	deps.AgentBuildExecutionEnv = func(context.Context, *store.Handle, store.AgentConsumer, Starter, string) ([]string, error) {
		return nil, errors.New("env")
	}
	if err := AgentCommand(ctx, deps, []string{"mcp", "codex"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected env error")
	}
	deps = fullAgentDeps(t)
	deps.AgentRegisterProcess = func(context.Context, Starter, string, int) error { return errors.New("register") }
	if err := AgentCommand(ctx, deps, []string{"launch", "codex", "--", "sh", "-c", "sleep 1"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected register error")
	}
	deps = fullAgentDeps(t)
	deps.StoreGetAgent = func(*store.Handle, string) (store.AgentConsumer, error) {
		return store.AgentConsumer{}, store.ErrConsumerNotFound
	}
	t.Setenv(secrettypes.EnvAgentProjectRoot, t.TempDir())
	if err := AgentCommand(ctx, deps, []string{"launch", "new", "--", "sh", "-c", "exit 0"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("launch fallback consumer: %v", err)
	}
	if got := envValue([]string{"A=B"}, "MISSING"); got != "" {
		t.Fatalf("missing env = %q", got)
	}
	if label, value := cliPair("Label", "Value")[0], cliPair("Label", "Value")[1]; label != "Label" || value != "Value" {
		t.Fatal("bad cliPair")
	}
}

func TestAgentHandlersAdditionalCoverageBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("registered help printer", func(t *testing.T) {
		deps := Deps{}
		orig := cmddispatch.PrintHelpTopicFn
		cmddispatch.PrintHelpTopicFn = func(w io.Writer, args []string) error {
			_, err := w.Write([]byte(strings.Join(args, "/")))
			return err
		}
		t.Cleanup(func() { cmddispatch.PrintHelpTopicFn = orig })
		var out bytes.Buffer
		if err := AgentCommand(ctx, deps, []string{"help"}, strings.NewReader(""), &out, io.Discard); err != nil {
			t.Fatalf("help: %v", err)
		}
		if out.String() != "agent" {
			t.Fatalf("help output = %q", out.String())
		}
	})

	t.Run("flag parse errors", func(t *testing.T) {
		deps := fullAgentDeps(t)
		for _, args := range [][]string{
			{"connect", "--bogus"},
			{"disconnect", "codex", "--bogus"},
			{"list", "--bogus"},
			{"list-supported", "--bogus"},
			{"mcp", "codex", "--bogus"},
			{"launch", "codex", "--bogus"},
		} {
			if err := AgentCommand(ctx, deps, args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
				t.Fatalf("expected parse error for %v", args)
			}
		}
	})

	t.Run("connect dependency errors", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*Deps)
			args   []string
		}{
			{"open vault", func(d *Deps) {
				d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
			}, []string{"connect", "codex"}},
			{"resolve project", func(d *Deps) {
				d.ResolveProjectRoot = func(context.Context, string) (string, bool, error) { return "", false, errors.New("root") }
			}, []string{"connect", "codex", "--project-root", t.TempDir()}},
			{"ensure binding", func(d *Deps) {
				d.EnsureProjectBinding = func(context.Context, *store.Handle, string) error { return errors.New("bind") }
			}, []string{"connect", "codex", "--project-root", t.TempDir()}},
			{"resolve paths", func(d *Deps) {
				d.ResolvePaths = func() (string, error) { return "", errors.New("paths") }
			}, []string{"connect", "codex"}},
			{"write config", func(d *Deps) {
				d.WriteAgentConfig = func(string, string) (AgentSetupOutcome, error) {
					return AgentSetupOutcome{}, errors.New("config")
				}
			}, []string{"connect", "codex"}},
			{"upsert", func(d *Deps) {
				d.StoreUpsertAgent = func(*store.Handle, store.AgentConsumer) (store.AgentConsumer, error) {
					return store.AgentConsumer{}, errors.New("upsert")
				}
			}, []string{"connect", "codex"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				deps := fullAgentDeps(t)
				tc.mutate(&deps)
				if err := AgentCommand(ctx, deps, tc.args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
					t.Fatal("expected error")
				}
			})
		}
	})

	t.Run("disconnect dependency errors", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*Deps)
		}{
			{"open vault", func(d *Deps) {
				d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
			}},
			{"remove config", func(d *Deps) {
				d.RemoveAgentConsumerConfig = func(string, string) error { return errors.New("remove") }
			}},
			{"delete", func(d *Deps) {
				d.StoreDeleteAgent = func(*store.Handle, string) error { return errors.New("delete") }
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				deps := fullAgentDeps(t)
				tc.mutate(&deps)
				if err := AgentCommand(ctx, deps, []string{"disconnect", "codex"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
					t.Fatal("expected error")
				}
			})
		}
	})

	t.Run("list dependency errors", func(t *testing.T) {
		deps := fullAgentDeps(t)
		deps.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		if err := AgentCommand(ctx, deps, []string{"list"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("expected list open error")
		}
		deps = fullAgentDeps(t)
		deps.AgentLoadSupportStatuses = func() ([]profiles.SupportStatus, error) { return nil, errors.New("profiles") }
		if err := AgentCommand(ctx, deps, []string{"list-supported"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("expected list-supported load error")
		}
	})

	t.Run("new flag set fallback", func(t *testing.T) {
		deps := fullAgentDeps(t)
		deps.NewFlagSet = nil
		if err := AgentCommand(ctx, deps, []string{"list"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
			t.Fatalf("fallback flagset: %v", err)
		}
	})

	t.Run("launch dependency and process branches", func(t *testing.T) {
		for _, args := range [][]string{
			{"launch", "--", "echo"},
		} {
			deps := fullAgentDeps(t)
			if err := AgentCommand(ctx, deps, args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
				t.Fatalf("expected usage error for %v", args)
			}
		}

		deps := fullAgentDeps(t)
		deps.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		if err := AgentCommand(ctx, deps, []string{"launch", "codex", "--", "echo"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("expected launch open error")
		}
		deps = fullAgentDeps(t)
		deps.StoreGetAgent = func(*store.Handle, string) (store.AgentConsumer, error) {
			return store.AgentConsumer{}, errors.New("get")
		}
		if err := AgentCommand(ctx, deps, []string{"launch", "codex", "--", "echo"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("expected launch get error")
		}
		deps = fullAgentDeps(t)
		deps.AgentNewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		if err := AgentCommand(ctx, deps, []string{"launch", "codex", "--", "echo"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("expected launch starter error")
		}
		deps = fullAgentDeps(t)
		deps.AgentBuildExecutionEnv = func(context.Context, *store.Handle, store.AgentConsumer, Starter, string) ([]string, error) {
			return nil, errors.New("env")
		}
		if err := AgentCommand(ctx, deps, []string{"launch", "codex", "--", "echo"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("expected launch env error")
		}
		deps = fullAgentDeps(t)
		deps.AgentUserShell = func() string { return "" }
		if err := AgentCommand(ctx, deps, []string{"shell", "codex", "--", "-c", "exit 0"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
			t.Fatalf("expected shell fallback success: %v", err)
		}
		deps = fullAgentDeps(t)
		deps.AgentExecCommandContext = func(ctx context.Context, name string, arg ...string) *exec.Cmd {
			return exec.CommandContext(ctx, filepath.Join(t.TempDir(), "missing"), arg...)
		}
		if err := AgentCommand(ctx, deps, []string{"launch", "codex", "--", "missing"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("expected command start error")
		}
		deps = fullAgentDeps(t)
		if err := AgentCommand(ctx, deps, []string{"launch", "codex", "--", "sh", "-c", "exit 7"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("expected command exit error")
		}
		deps = fullAgentDeps(t)
		origWait := agentWaitCommand
		agentWaitCommand = func(cmd *exec.Cmd) error {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return errors.New("wait")
		}
		t.Cleanup(func() { agentWaitCommand = origWait })
		if err := AgentCommand(ctx, deps, []string{"launch", "codex", "--", "sh", "-c", "sleep 1"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatal("expected command wait error")
		}
		agentWaitCommand = origWait
	})

	t.Run("mcp dependency errors", func(t *testing.T) {
		t.Run("missing consumer falls back to transient agent identity", func(t *testing.T) {
			deps := fullAgentDeps(t)
			deps.StoreGetAgent = func(*store.Handle, string) (store.AgentConsumer, error) {
				return store.AgentConsumer{}, store.ErrConsumerNotFound
			}
			var built store.AgentConsumer
			deps.AgentBuildExecutionEnv = func(_ context.Context, _ *store.Handle, consumer store.AgentConsumer, _ Starter, _ string) ([]string, error) {
				built = consumer
				return []string{secrettypes.EnvSessionToken + "=token"}, nil
			}
			var out bytes.Buffer
			if err := AgentCommand(ctx, deps, []string{"mcp", "codex-cli"}, strings.NewReader("ok"), &out, io.Discard); err != nil {
				t.Fatalf("mcp fallback: %v", err)
			}
			if built.Name != "codex-cli" || built.AgentID != "codex-cli" || built.ConfigPath != "/tmp/codex.toml" {
				t.Fatalf("unexpected fallback consumer: %+v", built)
			}
			if out.String() != "ok" {
				t.Fatalf("expected MCP server to run after fallback, got %q", out.String())
			}
		})

		t.Run("missing consumer fallback tolerates absent config paths dependency", func(t *testing.T) {
			deps := fullAgentDeps(t)
			deps.AgentConfigPaths = nil
			deps.StoreGetAgent = func(*store.Handle, string) (store.AgentConsumer, error) {
				return store.AgentConsumer{}, store.ErrConsumerNotFound
			}
			var built store.AgentConsumer
			deps.AgentBuildExecutionEnv = func(_ context.Context, _ *store.Handle, consumer store.AgentConsumer, _ Starter, _ string) ([]string, error) {
				built = consumer
				return []string{secrettypes.EnvSessionToken + "=token"}, nil
			}
			var out bytes.Buffer
			if err := AgentCommand(ctx, deps, []string{"mcp", "codex-cli"}, strings.NewReader("ok"), &out, io.Discard); err != nil {
				t.Fatalf("mcp fallback without config paths: %v", err)
			}
			if built.Name != "codex-cli" || built.AgentID != "codex-cli" || built.ConfigPath != "" {
				t.Fatalf("unexpected fallback consumer without config paths: %+v", built)
			}
		})

		cases := []struct {
			name   string
			mutate func(*Deps)
		}{
			{"open vault", func(d *Deps) {
				d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
			}},
			{"get", func(d *Deps) {
				d.StoreGetAgent = func(*store.Handle, string) (store.AgentConsumer, error) {
					return store.AgentConsumer{}, errors.New("get")
				}
			}},
			{"starter", func(d *Deps) {
				d.AgentNewStarter = func() (Starter, error) { return nil, errors.New("starter") }
			}},
			{"register", func(d *Deps) {
				d.AgentRegisterProcess = func(context.Context, Starter, string, int) error { return errors.New("register") }
			}},
			{"set env", func(d *Deps) {
				d.SetEnv = func(string, string) (func(), error) { return nil, errors.New("setenv") }
			}},
			{"serve", func(d *Deps) {
				d.AgentServeMCP = func(context.Context, io.Reader, io.Writer) error { return errors.New("serve") }
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				deps := fullAgentDeps(t)
				tc.mutate(&deps)
				if err := AgentCommand(ctx, deps, []string{"mcp", "codex"}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
					t.Fatal("expected error")
				}
			})
		}
	})
}
