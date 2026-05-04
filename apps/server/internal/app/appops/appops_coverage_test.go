package appops

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/cmddispatch"
	"github.com/gethasp/hasp/apps/server/internal/runner"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type fakeAppStarter struct{}

func (fakeAppStarter) EnsureDaemon(context.Context) error { return nil }
func (fakeAppStarter) Connect(context.Context) (*runtime.Client, error) {
	return nil, nil
}

func fullAppDeps(t *testing.T) Deps {
	t.Helper()
	return Deps{
		AppResolvePaths: func() (string, error) { return t.TempDir(), nil },
		AppWriteFile:    func(string, []byte, os.FileMode) error { return nil },
		AppReadFile:     func(string) ([]byte, error) { return []byte("file"), nil },
		AppMkdirAll:     func(string, os.FileMode) error { return nil },
		AppRemove:       func(string) error { return nil },
		AppUserShell:    func() string { return "sh" },
		AppCurrentShell: func() string {
			return "zsh"
		},
		AppUserHomeDir: func() (string, error) { return t.TempDir(), nil },
		StoreGetApp: func(_ *store.Handle, name string) (store.AppConsumer, error) {
			return store.AppConsumer{Name: name, Command: []string{"echo"}, LauncherPath: "/tmp/" + name, ProjectRoot: t.TempDir()}, nil
		},
		StoreListApps: func(*store.Handle) []store.AppConsumer {
			return []store.AppConsumer{{Name: "web", Command: []string{"echo"}}}
		},
		StoreUpsertApp: func(_ *store.Handle, consumer store.AppConsumer) (store.AppConsumer, error) {
			return consumer, nil
		},
		StoreDeleteApp: func(*store.Handle, string) error { return nil },
		AppExecuteConsumer: func(_ context.Context, _ *store.Handle, _ store.AppConsumer, command []string, stdout, _ io.Writer, _ Starter, action string) (runner.Result, error) {
			if stdout != nil {
				_, _ = stdout.Write([]byte(action + ":" + strings.Join(command, " ")))
			}
			return runner.Result{}, nil
		},
		AppInstallLauncher: func(name string) (string, error) { return "/tmp/" + name, nil },
		AppNewStarter:      func() (Starter, error) { return fakeAppStarter{}, nil },
		OpenVault:          func(context.Context) (*store.Handle, error) { return &store.Handle{}, nil },
		AppendAudit:        func(string, string, map[string]any) {},
		RenderJSONOrHuman: func(_ context.Context, stdout io.Writer, _ bool, _ any, human func(io.Writer) error) error {
			return human(stdout)
		},
		RenderConnectResult: func(out io.Writer, consumer store.AppConsumer, pathUpdate AppPathUpdate) error {
			_, err := out.Write([]byte(consumer.Name + ":" + pathUpdate.ConfigPath))
			return err
		},
		RenderInstallResult: func(out io.Writer, consumer store.AppConsumer, pathUpdate AppPathUpdate) error {
			_, err := out.Write([]byte(consumer.Name + ":" + pathUpdate.ConfigPath))
			return err
		},
		RenderConsumerList: func(out io.Writer, consumers []store.AppConsumer) error {
			_, err := out.Write([]byte(consumers[0].Name))
			return err
		},
		RenderSimpleAction: func(_ context.Context, out io.Writer, title string, lead string, pairs ...[2]string) error {
			_, err := out.Write([]byte(title + ":" + pairs[0][1]))
			return err
		},
		IsHelpArg:      nil,
		PrintHelpTopic: nil,
		NewFlagSet:     flag.NewFlagSet,
		ExpandUserPath: func(path string) (string, error) {
			return strings.Replace(path, "~", "/home/test", 1), nil
		},
		ResolveProjectRoot: func(_ context.Context, root string) (string, bool, error) {
			return "/repo/" + strings.TrimPrefix(root, "/home/test/"), true, nil
		},
		EnsureProjectBinding: func(context.Context, *store.Handle, string) error { return nil },
		GlobalJSON:           func(context.Context) bool { return false },
		WarnBareEnvRefs:      func(context.Context, io.Writer, map[string]string, string, string) {},
		StdinIsCharDevice:    func(io.Reader) bool { return false },
		PromptConnectMissing: func(_ io.Reader, _ io.Writer, cfg *AppConnectConfig) error {
			if cfg.Name == "" {
				cfg.Name = "prompted"
			}
			if cfg.Command == "" {
				cfg.Command = "echo prompted"
			}
			return nil
		},
		ValidateAppConsumerName: func(string) error { return nil },
		NormalizeConnectArgs:    nil,
		ConnectConsumer: func(_ context.Context, _ *store.Handle, cfg AppConnectConfig, _ io.Reader, _ io.Writer, _ io.Writer) (store.AppConsumer, AppPathUpdate, error) {
			return store.AppConsumer{Name: cfg.Name, Command: []string{cfg.Command}, ProjectRoot: cfg.ProjectRoot, LauncherPath: "/tmp/" + cfg.Name}, AppPathUpdate{ConfigPath: "/tmp/rc", Changed: true}, nil
		},
		InstallConsumer: func(_ context.Context, _ *store.Handle, name string, addToPath OptionalBool, _ io.Reader, _ io.Writer, _ io.Writer) (store.AppConsumer, AppPathUpdate, error) {
			return store.AppConsumer{Name: name, LauncherPath: "/tmp/" + name}, AppPathUpdate{ConfigPath: "/tmp/rc", Changed: addToPath.Value}, nil
		},
	}
}

func TestAppCommandSuccessPaths(t *testing.T) {
	deps := fullAppDeps(t)
	ctx := context.Background()
	var out bytes.Buffer

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"help", []string{"help"}, "Usage: hasp app"},
		{"connect", []string{"connect", "web", "--cmd", "npm start", "--project-root", "~/repo", "--env", "TOKEN=@TOKEN", "--file", "CONFIG=@CONFIG", "--install", "--add-to-path=never"}, "web:/tmp/rc"},
		{"connect target default root", []string{"connect", "web", "--target", "server.dev", "--cmd", "npm start"}, "web:/tmp/rc"},
		{"run", []string{"run", "web", "--", "arg"}, "run:echo arg"},
		{"shell", []string{"shell", "web", "--", "-c", "true"}, "shell:sh -l -c true"},
		{"install", []string{"install", "web", "--add-to-path=always"}, "web:/tmp/rc"},
		{"disconnect", []string{"disconnect", "web"}, "App disconnected:web"},
		{"list", []string{"list"}, "web"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out.Reset()
			if err := AppCommand(ctx, deps, tc.args, strings.NewReader(""), &out, io.Discard); err != nil {
				t.Fatalf("AppCommand(%v): %v", tc.args, err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("output %q does not contain %q", out.String(), tc.want)
			}
		})
	}
}

func TestAppCommandFallbacksAndFlagValues(t *testing.T) {
	deps := fullAppDeps(t)
	deps.NewFlagSet = nil
	deps.IsHelpArg = nil
	deps.PrintHelpTopic = nil
	if err := AppCommand(context.Background(), deps, []string{"-help"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("fallback help: %v", err)
	}
	if err := AppCommand(context.Background(), deps, []string{"list"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("fallback flag set: %v", err)
	}
	origPrintHelp := cmddispatch.PrintHelpTopicFn
	t.Cleanup(func() { cmddispatch.PrintHelpTopicFn = origPrintHelp })
	cmddispatch.PrintHelpTopicFn = func(w io.Writer, args []string) error {
		_, err := w.Write([]byte(strings.Join(args, "/")))
		return err
	}
	var helpOut bytes.Buffer
	deps.PrintHelpTopic = nil
	if err := AppCommand(context.Background(), deps, []string{"help"}, strings.NewReader(""), &helpOut, io.Discard); err != nil {
		t.Fatalf("cmddispatch help: %v", err)
	}
	if helpOut.String() != "app" {
		t.Fatalf("cmddispatch help output %q", helpOut.String())
	}
	deps = fullAppDeps(t)
	deps.NormalizeConnectArgs = func(args []string) []string {
		return append(args, "--add-to-path=always")
	}
	if err := AppCommand(context.Background(), deps, []string{"connect", "web", "--cmd", "x"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("custom normalize args: %v", err)
	}
	if name, args := consumerNameAndArgs([]string{"--json"}); name != "" || len(args) != 1 {
		t.Fatalf("consumerNameAndArgs flag first = %q, %v", name, args)
	}
	if got := defaultNormalizeConnectArgs([]string{"--install", "--cmd", "x"}); got[0] != "--install=always" || got[1] != "--cmd" {
		t.Fatalf("defaultNormalizeConnectArgs = %v", got)
	}
	var mappings map[string]string
	mapFlag := newStringMapFlag(&mappings)
	if mapFlag.String() != "" {
		t.Fatalf("empty map String = %q", mapFlag.String())
	}
	if err := mapFlag.Set(" A = @A "); err != nil {
		t.Fatalf("map set: %v", err)
	}
	if !strings.Contains(mapFlag.String(), "A=@A") {
		t.Fatalf("map String = %q", mapFlag.String())
	}
	if err := mapFlag.Set("bad"); err == nil {
		t.Fatal("expected bad map value error")
	}
	var opt OptionalBool
	optFlag := newOptionalBoolFlag(&opt)
	if optFlag.String() != "" {
		t.Fatalf("unset optional String = %q", optFlag.String())
	}
	if err := optFlag.Set("always"); err != nil || optFlag.String() != "true" {
		t.Fatalf("always set err=%v string=%q", err, optFlag.String())
	}
	if err := optFlag.Set("never"); err != nil || optFlag.String() != "false" {
		t.Fatalf("never set err=%v string=%q", err, optFlag.String())
	}
	if err := optFlag.Set("sometimes"); err == nil {
		t.Fatal("expected invalid optional bool error")
	}
	if label, value := cliPair("Name", "web")[0], cliPair("Name", "web")[1]; label != "Name" || value != "web" {
		t.Fatal("bad cliPair")
	}
}

func TestAppCommandErrorBranches(t *testing.T) {
	ctx := context.Background()
	base := fullAppDeps(t)
	cases := []struct {
		name string
		args []string
		mut  func(*Deps)
	}{
		{"unknown", []string{"wat"}, nil},
		{"connect parse", []string{"connect", "web", "--bad"}, nil},
		{"connect extra arg", []string{"connect", "web", "--cmd", "x", "extra"}, nil},
		{"connect missing name", []string{"connect", "--cmd", "x"}, nil},
		{"connect missing cmd", []string{"connect", "web"}, nil},
		{"connect invalid name", []string{"connect", "web", "--cmd", "x"}, func(d *Deps) {
			d.ValidateAppConsumerName = func(string) error { return errors.New("name") }
		}},
		{"connect dotenv env missing", []string{"connect", "web", "--cmd", "x", "--dotenv", "A=@A"}, nil},
		{"connect target with env", []string{"connect", "web", "--target", "server.dev", "--env", "TOKEN=@TOKEN", "--cmd", "x"}, nil},
		{"connect expand", []string{"connect", "web", "--cmd", "x", "--project-root", "~"}, func(d *Deps) {
			d.ExpandUserPath = func(string) (string, error) { return "", errors.New("expand") }
		}},
		{"connect open nil", []string{"connect", "web", "--cmd", "x"}, func(d *Deps) { d.OpenVault = nil }},
		{"connect open", []string{"connect", "web", "--cmd", "x"}, func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"connect resolve", []string{"connect", "web", "--cmd", "x", "--project-root", "/r"}, func(d *Deps) {
			d.ResolveProjectRoot = func(context.Context, string) (string, bool, error) { return "", false, errors.New("root") }
		}},
		{"connect bind", []string{"connect", "web", "--cmd", "x", "--project-root", "/r"}, func(d *Deps) {
			d.EnsureProjectBinding = func(context.Context, *store.Handle, string) error { return errors.New("bind") }
		}},
		{"connect consumer nil", []string{"connect", "web", "--cmd", "x"}, func(d *Deps) { d.ConnectConsumer = nil }},
		{"connect consumer", []string{"connect", "web", "--cmd", "x"}, func(d *Deps) {
			d.ConnectConsumer = func(context.Context, *store.Handle, AppConnectConfig, io.Reader, io.Writer, io.Writer) (store.AppConsumer, AppPathUpdate, error) {
				return store.AppConsumer{}, AppPathUpdate{}, errors.New("connect")
			}
		}},
		{"connect prompt", []string{"connect", "web", "--cmd", "x"}, func(d *Deps) {
			d.StdinIsCharDevice = func(io.Reader) bool { return true }
			d.PromptConnectMissing = func(io.Reader, io.Writer, *AppConnectConfig) error { return errors.New("prompt") }
		}},
		{"run parse", []string{"run", "web", "--bad"}, nil},
		{"run missing name", []string{"run"}, nil},
		{"run open nil", []string{"run", "web"}, func(d *Deps) { d.OpenVault = nil }},
		{"run open", []string{"run", "web"}, func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"run get", []string{"run", "web"}, func(d *Deps) {
			d.StoreGetApp = func(*store.Handle, string) (store.AppConsumer, error) { return store.AppConsumer{}, errors.New("get") }
		}},
		{"run starter", []string{"run", "web"}, func(d *Deps) {
			d.AppNewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		}},
		{"run execute nil", []string{"run", "web"}, func(d *Deps) { d.AppExecuteConsumer = nil }},
		{"run execute", []string{"run", "web"}, func(d *Deps) {
			d.AppExecuteConsumer = func(context.Context, *store.Handle, store.AppConsumer, []string, io.Writer, io.Writer, Starter, string) (runner.Result, error) {
				return runner.Result{}, errors.New("execute")
			}
		}},
		{"run exit", []string{"run", "web"}, func(d *Deps) {
			d.AppExecuteConsumer = func(context.Context, *store.Handle, store.AppConsumer, []string, io.Writer, io.Writer, Starter, string) (runner.Result, error) {
				return runner.Result{ExitCode: 7}, nil
			}
		}},
		{"shell parse", []string{"shell", "web", "--bad"}, nil},
		{"shell missing name", []string{"shell"}, nil},
		{"shell open nil", []string{"shell", "web"}, func(d *Deps) { d.OpenVault = nil }},
		{"shell open", []string{"shell", "web"}, func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"shell get", []string{"shell", "web"}, func(d *Deps) {
			d.StoreGetApp = func(*store.Handle, string) (store.AppConsumer, error) { return store.AppConsumer{}, errors.New("get") }
		}},
		{"shell starter", []string{"shell", "web"}, func(d *Deps) {
			d.AppNewStarter = func() (Starter, error) { return nil, errors.New("starter") }
		}},
		{"shell execute nil", []string{"shell", "web"}, func(d *Deps) { d.AppExecuteConsumer = nil }},
		{"shell execute", []string{"shell", "web"}, func(d *Deps) {
			d.AppExecuteConsumer = func(context.Context, *store.Handle, store.AppConsumer, []string, io.Writer, io.Writer, Starter, string) (runner.Result, error) {
				return runner.Result{}, errors.New("execute")
			}
		}},
		{"shell exit", []string{"shell", "web"}, func(d *Deps) {
			d.AppExecuteConsumer = func(context.Context, *store.Handle, store.AppConsumer, []string, io.Writer, io.Writer, Starter, string) (runner.Result, error) {
				return runner.Result{ExitCode: 2}, nil
			}
		}},
		{"install parse", []string{"install", "web", "--bad"}, nil},
		{"install usage", []string{"install"}, nil},
		{"install open nil", []string{"install", "web"}, func(d *Deps) { d.OpenVault = nil }},
		{"install open", []string{"install", "web"}, func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"install consumer nil", []string{"install", "web"}, func(d *Deps) { d.InstallConsumer = nil }},
		{"install consumer", []string{"install", "web"}, func(d *Deps) {
			d.InstallConsumer = func(context.Context, *store.Handle, string, OptionalBool, io.Reader, io.Writer, io.Writer) (store.AppConsumer, AppPathUpdate, error) {
				return store.AppConsumer{}, AppPathUpdate{}, errors.New("install")
			}
		}},
		{"disconnect parse", []string{"disconnect", "web", "--bad"}, nil},
		{"disconnect usage", []string{"disconnect"}, nil},
		{"disconnect open nil", []string{"disconnect", "web"}, func(d *Deps) { d.OpenVault = nil }},
		{"disconnect open", []string{"disconnect", "web"}, func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"disconnect get", []string{"disconnect", "web"}, func(d *Deps) {
			d.StoreGetApp = func(*store.Handle, string) (store.AppConsumer, error) { return store.AppConsumer{}, errors.New("get") }
		}},
		{"disconnect delete", []string{"disconnect", "web"}, func(d *Deps) {
			d.StoreDeleteApp = func(*store.Handle, string) error { return errors.New("delete") }
		}},
		{"disconnect remove", []string{"disconnect", "web"}, func(d *Deps) {
			d.AppRemove = func(string) error { return errors.New("remove") }
		}},
		{"disconnect rollback", []string{"disconnect", "web"}, func(d *Deps) {
			d.AppRemove = func(string) error { return errors.New("remove") }
			d.StoreUpsertApp = func(*store.Handle, store.AppConsumer) (store.AppConsumer, error) {
				return store.AppConsumer{}, errors.New("rollback")
			}
		}},
		{"list parse", []string{"list", "--bad"}, nil},
		{"list open nil", []string{"list"}, func(d *Deps) { d.OpenVault = nil }},
		{"list open", []string{"list"}, func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := base
			if tc.mut != nil {
				tc.mut(&deps)
			}
			if err := AppCommand(ctx, deps, tc.args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
				t.Fatalf("expected error for %v", tc.args)
			}
		})
	}
}

func TestAppCommandNilRenderersAndOptionalBranches(t *testing.T) {
	ctx := context.Background()

	deps := fullAppDeps(t)
	deps.RenderJSONOrHuman = nil
	if err := AppCommand(ctx, deps, []string{"connect", "web", "--cmd", "x"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("connect nil renderer: %v", err)
	}
	if err := AppCommand(ctx, deps, []string{"install", "web"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("install nil renderer: %v", err)
	}
	if err := AppCommand(ctx, deps, []string{"disconnect", "web"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("disconnect nil renderer: %v", err)
	}
	if err := AppCommand(ctx, deps, []string{"list"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("list nil renderer: %v", err)
	}

	deps = fullAppDeps(t)
	deps.RenderConnectResult = nil
	deps.RenderInstallResult = nil
	deps.RenderSimpleAction = nil
	deps.RenderConsumerList = nil
	var out bytes.Buffer
	if err := AppCommand(ctx, deps, []string{"connect", "web", "--cmd", "x", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("connect nil connect renderer: %v", err)
	}
	if err := AppCommand(ctx, deps, []string{"install", "web", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("install nil install renderer: %v", err)
	}
	if err := AppCommand(ctx, deps, []string{"disconnect", "web", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("disconnect nil action renderer: %v", err)
	}
	if err := AppCommand(ctx, deps, []string{"list", "--json"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("list nil list renderer: %v", err)
	}

	deps = fullAppDeps(t)
	deps.AppUserShell = func() string { return "" }
	if err := AppCommand(ctx, deps, []string{"shell", "web"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("shell fallback shell: %v", err)
	}
	deps = fullAppDeps(t)
	deps.AppNewStarter = nil
	if err := AppCommand(ctx, deps, []string{"run", "web"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("run nil starter: %v", err)
	}
	if err := AppCommand(ctx, deps, []string{"shell", "web"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("shell nil starter: %v", err)
	}
	deps = fullAppDeps(t)
	deps.AppRemove = func(string) error { return os.ErrNotExist }
	if err := AppCommand(ctx, deps, []string{"disconnect", "web"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("disconnect remove not-exist: %v", err)
	}
}
