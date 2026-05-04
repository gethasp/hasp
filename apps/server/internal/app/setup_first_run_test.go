package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSetupOptionalFirstRunActions(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	storeHandle, err := store.New(&memorySetupKeyring{})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := storeHandle.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := storeHandle.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	input := bytes.NewBufferString("y\nAPI_TOKEN\nabc123\nn\ny\nmyapp\ntrue\ny\nAPI_TOKEN\nenv\nOPENAI_API_KEY\nn\ny\nn\n")
	var out bytes.Buffer
	prompt := newSetupPrompter(input, &out)

	added, apps, err := setupOptionalFirstRunActions(context.Background(), prompt, handle, "")
	if err != nil {
		t.Fatalf("setup optional first-run actions: %v", err)
	}
	if len(added) != 1 || added[0].Name != "API_TOKEN" {
		t.Fatalf("unexpected added secrets %+v", added)
	}
	if len(apps) != 1 || apps[0].Name != "myapp" {
		t.Fatalf("unexpected app outcomes %+v", apps)
	}
	if apps[0].LauncherPath == "" {
		t.Fatalf("expected launcher path in app outcome %+v", apps[0])
	}
	if _, err := os.Stat(apps[0].LauncherPath); err != nil {
		t.Fatalf("expected launcher file: %v", err)
	}
	consumer, err := handle.GetAppConsumer("myapp")
	if err != nil {
		t.Fatalf("get app consumer: %v", err)
	}
	if consumer.ProjectRoot != "" {
		t.Fatalf("expected machine-scoped app consumer, got %+v", consumer)
	}
	if len(consumer.Bindings) != 1 || consumer.Bindings[0].Target != "OPENAI_API_KEY" {
		t.Fatalf("unexpected app bindings %+v", consumer.Bindings)
	}
	if strings.Contains(out.String(), "rollback failed") {
		t.Fatalf("unexpected rollback output %q", out.String())
	}
}

func TestSetupOptionalFirstRunActionsWithRepoChoices(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	storeHandle, err := store.New(&memorySetupKeyring{})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := storeHandle.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := storeHandle.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, _, _, err := ensureProjectBindingExplicit(context.Background(), handle, projectRoot); err != nil {
		t.Fatalf("ensure binding: %v", err)
	}

	input := bytes.NewBufferString("y\nTOKEN\nabc123\nn\ny\ny\ny\nrepoapp\ntrue\ny\nTOKEN\nenv\nAPI_TOKEN\nn\nn\n")
	prompt := newSetupPrompter(input, io.Discard)

	added, apps, err := setupOptionalFirstRunActions(context.Background(), prompt, handle, projectRoot)
	if err != nil {
		t.Fatalf("setup optional first-run actions with repo: %v", err)
	}
	if len(added) != 1 || added[0].Reference == "" {
		t.Fatalf("expected repo exposure for added secret, got %+v", added)
	}
	if len(apps) != 1 || apps[0].ProjectRoot != projectRoot {
		t.Fatalf("expected repo-scoped app outcome, got %+v", apps)
	}
}

func TestSetupOptionalFirstRunActionCoverageBranches(t *testing.T) {
	lockAppSeams(t)

	t.Run("nil prompt is a no-op", func(t *testing.T) {
		added, apps, err := setupOptionalFirstRunActions(context.Background(), nil, nil, "")
		if err != nil || len(added) != 0 || len(apps) != 0 {
			t.Fatalf("expected nil prompt to be a no-op, got added=%+v apps=%+v err=%v", added, apps, err)
		}
	})

	t.Run("skip add secret and connect app", func(t *testing.T) {
		homeDir := t.TempDir()
		t.Setenv("HASP_HOME", homeDir)
		t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

		storeHandle, err := store.New(&memorySetupKeyring{})
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		if err := storeHandle.Init(context.Background(), "correct horse battery staple"); err != nil {
			t.Fatalf("init store: %v", err)
		}
		handle, err := storeHandle.OpenWithPassword(context.Background(), "correct horse battery staple")
		if err != nil {
			t.Fatalf("open store: %v", err)
		}

		added, apps, err := setupOptionalFirstRunActions(context.Background(), newSetupPrompter(bytes.NewBufferString("n\nn\n"), io.Discard), handle, "")
		if err != nil || len(added) != 0 || len(apps) != 0 {
			t.Fatalf("expected skip flow, got added=%+v apps=%+v err=%v", added, apps, err)
		}
	})

	t.Run("add secret prompt failure propagates", func(t *testing.T) {
		homeDir := t.TempDir()
		t.Setenv("HASP_HOME", homeDir)
		t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

		storeHandle, err := store.New(&memorySetupKeyring{})
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		if err := storeHandle.Init(context.Background(), "correct horse battery staple"); err != nil {
			t.Fatalf("init store: %v", err)
		}
		handle, err := storeHandle.OpenWithPassword(context.Background(), "correct horse battery staple")
		if err != nil {
			t.Fatalf("open store: %v", err)
		}

		_, _, err = setupOptionalFirstRunActions(context.Background(), newSetupPrompter(io.MultiReader(strings.NewReader("y\n"), setupErrReader{}), io.Discard), handle, "")
		if err == nil {
			t.Fatal("expected add-secret prompt failure")
		}
	})

	t.Run("add secret collision can skip", func(t *testing.T) {
		homeDir := t.TempDir()
		t.Setenv("HASP_HOME", homeDir)
		t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

		storeHandle, err := store.New(&memorySetupKeyring{})
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		if err := storeHandle.Init(context.Background(), "correct horse battery staple"); err != nil {
			t.Fatalf("init store: %v", err)
		}
		handle, err := storeHandle.OpenWithPassword(context.Background(), "correct horse battery staple")
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		if _, err := handle.UpsertItem("API_TOKEN", store.ItemKindKV, []byte("old"), store.ItemMetadata{}); err != nil {
			t.Fatalf("seed item: %v", err)
		}

		added, err := setupMaybeAddSecretsNow(context.Background(), newSetupPrompter(bytes.NewBufferString("y\nAPI_TOKEN\nnewvalue\nn\n3\n"), io.Discard), handle, "")
		if err != nil {
			t.Fatalf("setupMaybeAddSecretsNow skip collision: %v", err)
		}
		if len(added) != 1 || added[0].Outcome != "skipped" {
			t.Fatalf("expected skipped collision outcome, got %+v", added)
		}
	})

	t.Run("connect app validation error propagates", func(t *testing.T) {
		homeDir := t.TempDir()
		t.Setenv("HASP_HOME", homeDir)
		t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

		storeHandle, err := store.New(&memorySetupKeyring{})
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		if err := storeHandle.Init(context.Background(), "correct horse battery staple"); err != nil {
			t.Fatalf("init store: %v", err)
		}
		handle, err := storeHandle.OpenWithPassword(context.Background(), "correct horse battery staple")
		if err != nil {
			t.Fatalf("open store: %v", err)
		}

		_, _, err = setupOptionalFirstRunActions(context.Background(), newSetupPrompter(bytes.NewBufferString("n\ny\n\n\n"), io.Discard), handle, "")
		if err == nil || !strings.Contains(err.Error(), "app name is required") {
			t.Fatalf("expected app-name validation error, got %v", err)
		}
	})

	t.Run("setupMaybeAddSecretsNow residual error branches", func(t *testing.T) {
		homeDir := t.TempDir()
		t.Setenv("HASP_HOME", homeDir)
		t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

		storeHandle, err := store.New(&memorySetupKeyring{})
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		if err := storeHandle.Init(context.Background(), "correct horse battery staple"); err != nil {
			t.Fatalf("init store: %v", err)
		}
		handle, err := storeHandle.OpenWithPassword(context.Background(), "correct horse battery staple")
		if err != nil {
			t.Fatalf("open store: %v", err)
		}

		t.Run("expose prompt failure", func(t *testing.T) {
			_, err := setupMaybeAddSecretsNow(context.Background(), newSetupPrompter(io.MultiReader(strings.NewReader("y\nTOKEN\nvalue\nn\n"), setupErrReader{}), io.Discard), handle, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), "read fail") {
				t.Fatalf("expected expose prompt failure, got %v", err)
			}
		})

		t.Run("collision prompt failure", func(t *testing.T) {
			if _, err := handle.UpsertItem("TOKEN", store.ItemKindKV, []byte("old"), store.ItemMetadata{}); err != nil {
				t.Fatalf("seed item: %v", err)
			}
			_, err := setupMaybeAddSecretsNow(context.Background(), newSetupPrompter(io.MultiReader(strings.NewReader("y\nTOKEN\nvalue\nn\n"), setupErrReader{}), io.Discard), handle, "")
			if err == nil || !strings.Contains(err.Error(), "read fail") {
				t.Fatalf("expected collision prompt failure, got %v", err)
			}
		})

		t.Run("upsert failure", func(t *testing.T) {
			origUpsert := secretUpsertItemFn
			defer func() { secretUpsertItemFn = origUpsert }()
			secretUpsertItemFn = func(*store.Handle, string, store.ItemKind, []byte, store.ItemMetadata) (store.Item, error) {
				return store.Item{}, errors.New("upsert fail")
			}
			_, err := setupMaybeAddSecretsNow(context.Background(), newSetupPrompter(bytes.NewBufferString("y\nNEW_TOKEN\nvalue\nn\n"), io.Discard), handle, "")
			if err == nil || !strings.Contains(err.Error(), "upsert fail") {
				t.Fatalf("expected upsert failure, got %v", err)
			}
		})

		t.Run("bind failure", func(t *testing.T) {
			origBind := secretBindItemAliasFn
			defer func() { secretBindItemAliasFn = origBind }()
			secretBindItemAliasFn = func(*store.Handle, context.Context, string, string) (string, error) {
				return "", errors.New("bind fail")
			}
			_, err := setupMaybeAddSecretsNow(context.Background(), newSetupPrompter(bytes.NewBufferString("y\nBIND_TOKEN\nvalue\nn\ny\n"), io.Discard), handle, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), "bind fail") {
				t.Fatalf("expected bind failure, got %v", err)
			}
		})
	})

	t.Run("setupMaybeConnectAppNow residual error branches", func(t *testing.T) {
		homeDir := t.TempDir()
		t.Setenv("HASP_HOME", homeDir)
		t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

		storeHandle, err := store.New(&memorySetupKeyring{})
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		if err := storeHandle.Init(context.Background(), "correct horse battery staple"); err != nil {
			t.Fatalf("init store: %v", err)
		}
		handle, err := storeHandle.OpenWithPassword(context.Background(), "correct horse battery staple")
		if err != nil {
			t.Fatalf("open store: %v", err)
		}

		t.Run("repo prompt failure", func(t *testing.T) {
			_, err := setupMaybeConnectAppNow(context.Background(), newSetupPrompter(io.MultiReader(strings.NewReader("y\n"), setupErrReader{}), io.Discard), handle, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), "read fail") {
				t.Fatalf("expected repo prompt failure, got %v", err)
			}
		})

		t.Run("prompt-missing error", func(t *testing.T) {
			_, err := setupMaybeConnectAppNow(context.Background(), newSetupPrompter(io.MultiReader(strings.NewReader("y\n"), setupErrReader{}), io.Discard), handle, "")
			if err == nil || !strings.Contains(err.Error(), "read fail") {
				t.Fatalf("expected prompt-missing failure, got %v", err)
			}
		})

		t.Run("command required", func(t *testing.T) {
			_, err := setupMaybeConnectAppNow(context.Background(), newSetupPrompter(bytes.NewBufferString("y\napp\n\nn\n"), io.Discard), handle, "")
			if err == nil || !strings.Contains(err.Error(), "app command is required") {
				t.Fatalf("expected command-required failure, got %v", err)
			}
		})

		t.Run("invalid app name", func(t *testing.T) {
			_, err := setupMaybeConnectAppNow(context.Background(), newSetupPrompter(bytes.NewBufferString("y\n../bad\ntrue\nn\n"), io.Discard), handle, "")
			if err == nil || !strings.Contains(err.Error(), "invalid app name") {
				t.Fatalf("expected invalid-name failure, got %v", err)
			}
		})

		t.Run("install launcher prompt failure", func(t *testing.T) {
			_, err := setupMaybeConnectAppNow(context.Background(), newSetupPrompter(io.MultiReader(strings.NewReader("y\napp\ntrue\nn\n"), setupErrReader{}), io.Discard), handle, "")
			if err == nil || !strings.Contains(err.Error(), "read fail") {
				t.Fatalf("expected install prompt failure, got %v", err)
			}
		})

		t.Run("resolve paths failure", func(t *testing.T) {
			origResolve := appResolvePathsFn
			defer func() { appResolvePathsFn = origResolve }()
			appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{}, errors.New("resolve fail") }
			_, err := setupMaybeConnectAppNow(context.Background(), newSetupPrompter(bytes.NewBufferString("y\napp\ntrue\nn\ny\n"), io.Discard), handle, "")
			if err == nil || !strings.Contains(err.Error(), "resolve fail") {
				t.Fatalf("expected resolve paths failure, got %v", err)
			}
		})

		t.Run("add-to-path prompt failure", func(t *testing.T) {
			origResolve := appResolvePathsFn
			defer func() { appResolvePathsFn = origResolve }()
			appResolvePathsFn = func() (paths.Paths, error) { return paths.Paths{HomeDir: t.TempDir()}, nil }
			_, err := setupMaybeConnectAppNow(context.Background(), newSetupPrompter(io.MultiReader(strings.NewReader("y\napp\ntrue\nn\ny\n"), setupErrReader{}), io.Discard), handle, "")
			if err == nil || !strings.Contains(err.Error(), "read fail") {
				t.Fatalf("expected add-to-path prompt failure, got %v", err)
			}
		})

		t.Run("connect consumer failure", func(t *testing.T) {
			_, err := setupMaybeConnectAppNow(context.Background(), newSetupPrompter(bytes.NewBufferString("y\napp\ntrue\ny\nMISSING\nenv\nOPENAI_API_KEY\nn\nn\n"), io.Discard), handle, "")
			if err == nil || !strings.Contains(err.Error(), "item not found") {
				t.Fatalf("expected connect consumer failure, got %v", err)
			}
		})
	})

	t.Run("setupPromptReader prefers prompt file", func(t *testing.T) {
		file, err := os.CreateTemp(t.TempDir(), "prompt-reader")
		if err != nil {
			t.Fatalf("create temp file: %v", err)
		}
		defer file.Close()
		reader := bytes.NewBufferString("fallback")
		prompt := newSetupPrompter(reader, io.Discard)
		if got := setupPromptReader(prompt); got != prompt.reader {
			t.Fatalf("expected reader fallback, got %T", got)
		}
		prompt.file = file
		if got := setupPromptReader(prompt); got != file {
			t.Fatalf("expected file reader, got %T", got)
		}
	})
}
