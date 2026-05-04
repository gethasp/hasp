package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestAppConsumerLifecycleAndDeliveryModes(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")
	starter := newDaemonTestStarter(t)

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set API_TOKEN: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "CERT_FILE", "--kind", "file", "--value", "certificate-data"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set CERT_FILE: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "DATABASE_URL", "--value", "postgres://localhost"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set DATABASE_URL: %v", err)
	}

	var connectOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{
		"app", "connect", "myapp", "--json",
		"--project-root", projectRoot,
		"--cmd", "printf '%s:%s' \"$OPENAI_API_KEY\" \"$1\"",
		"--env", "OPENAI_API_KEY=API_TOKEN",
		"--install",
	}, bytes.NewBuffer(nil), &connectOut, &connectOut, starter); err != nil {
		t.Fatalf("app connect: %v", err)
	}
	var connectPayload map[string]any
	if err := json.Unmarshal(connectOut.Bytes(), &connectPayload); err != nil {
		t.Fatalf("decode app connect output: %v", err)
	}
	consumer := connectPayload["consumer"].(map[string]any)
	launcherPath := consumer["launcher_path"].(string)
	if launcherPath == "" {
		t.Fatal("expected launcher path")
	}
	if _, err := os.Stat(launcherPath); err != nil {
		t.Fatalf("launcher missing: %v", err)
	}
	launcherData, err := os.ReadFile(launcherPath)
	if err != nil {
		t.Fatalf("read launcher: %v", err)
	}
	if !strings.Contains(string(launcherData), "app run \"myapp\"") {
		t.Fatalf("unexpected launcher script: %s", string(launcherData))
	}

	var runOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"app", "run", "myapp", "extra-arg"}, bytes.NewBuffer(nil), &runOut, io.Discard, starter); err != nil {
		t.Fatalf("app run: %v", err)
	}
	if strings.Contains(runOut.String(), "abc123") {
		t.Fatalf("expected app run output to be redacted, got %q", runOut.String())
	}
	if !strings.Contains(runOut.String(), "extra-arg") {
		t.Fatalf("expected app run to forward trailing args, got %q", runOut.String())
	}

	origShell := appUserShellFn
	defer func() { appUserShellFn = origShell }()
	shellScript := filepath.Join(t.TempDir(), "consumer-shell.sh")
	if err := os.WriteFile(shellScript, []byte("#!/usr/bin/env bash\narg=\"$1\"\nif [ \"$arg\" = \"-l\" ]; then\n  arg=\"$2\"\nfi\nprintf '%s:%s' \"$OPENAI_API_KEY\" \"$arg\"\n"), 0o755); err != nil {
		t.Fatalf("write shell script: %v", err)
	}
	appUserShellFn = func() string { return shellScript }
	var shellOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"app", "shell", "myapp", "shell-arg"}, bytes.NewBuffer(nil), &shellOut, io.Discard, starter); err != nil {
		t.Fatalf("app shell: %v", err)
	}
	if strings.Contains(shellOut.String(), "abc123") {
		t.Fatalf("expected app shell output to be redacted, got %q", shellOut.String())
	}
	if !strings.Contains(shellOut.String(), "shell-arg") {
		t.Fatalf("expected app shell to forward trailing args, got %q", shellOut.String())
	}

	var listOut bytes.Buffer
	if err := Run(context.Background(), []string{"app", "list", "--json"}, bytes.NewBuffer(nil), &listOut, &listOut); err != nil {
		t.Fatalf("app list: %v", err)
	}
	if !strings.Contains(listOut.String(), "\"myapp\"") {
		t.Fatalf("expected myapp in list output, got %q", listOut.String())
	}

	var installOut bytes.Buffer
	if err := Run(context.Background(), []string{"app", "install", "myapp", "--json"}, bytes.NewBuffer(nil), &installOut, &installOut); err != nil {
		t.Fatalf("app install: %v", err)
	}
	if !strings.Contains(installOut.String(), launcherPath) {
		t.Fatalf("expected launcher path in install output, got %q", installOut.String())
	}

	var fileConnectOut bytes.Buffer
	if err := Run(context.Background(), []string{
		"app", "connect", "fileapp",
		"--project-root", projectRoot,
		"--cmd", "cat \"$CERT_PATH\"",
		"--file", "CERT_PATH=CERT_FILE",
	}, bytes.NewBuffer(nil), &fileConnectOut, &fileConnectOut); err != nil {
		t.Fatalf("file app connect: %v", err)
	}
	var fileRunOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"app", "run", "fileapp"}, bytes.NewBuffer(nil), &fileRunOut, io.Discard, starter); err != nil {
		t.Fatalf("file app run: %v", err)
	}
	if strings.Contains(fileRunOut.String(), "certificate-data") {
		t.Fatalf("expected file app run output to be redacted, got %q", fileRunOut.String())
	}

	var dotenvConnectOut bytes.Buffer
	if err := Run(context.Background(), []string{
		"app", "connect", "dotenvapp",
		"--project-root", projectRoot,
		"--cmd", "cat \"$ENV_FILE\"",
		"--dotenv-env", "ENV_FILE",
		"--dotenv", "DATABASE_URL=DATABASE_URL",
	}, bytes.NewBuffer(nil), &dotenvConnectOut, &dotenvConnectOut); err != nil {
		t.Fatalf("dotenv app connect: %v", err)
	}
	var dotenvRunOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"app", "run", "dotenvapp"}, bytes.NewBuffer(nil), &dotenvRunOut, io.Discard, starter); err != nil {
		t.Fatalf("dotenv app run: %v", err)
	}
	if strings.Contains(dotenvRunOut.String(), "postgres://localhost") {
		t.Fatalf("expected dotenv app output to be redacted, got %q", dotenvRunOut.String())
	}

	if err := Run(context.Background(), []string{
		"app", "connect", "portableapp",
		"--cmd", "printf '%s' \"$OPENAI_API_KEY\"",
		"--env", "OPENAI_API_KEY=API_TOKEN",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("portable app connect without project root: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault handle after portable connect: %v", err)
	}
	portableConsumer, err := handle.GetAppConsumer("portableapp")
	if err != nil {
		t.Fatalf("get portable app consumer: %v", err)
	}
	if portableConsumer.ProjectRoot != "" {
		t.Fatalf("expected portable app consumer to be machine-scoped, got %q", portableConsumer.ProjectRoot)
	}
	var portableRunOut bytes.Buffer
	if err := runWithStarter(context.Background(), []string{"app", "run", "portableapp"}, bytes.NewBuffer(nil), &portableRunOut, io.Discard, starter); err != nil {
		t.Fatalf("portable app run: %v", err)
	}
	if strings.Contains(portableRunOut.String(), "abc123") {
		t.Fatalf("expected portable app run output to be redacted, got %q", portableRunOut.String())
	}

	launcherBlockPath := filepath.Join(homeDir, "bin", "occupied")
	if err := os.MkdirAll(filepath.Dir(launcherBlockPath), 0o700); err != nil {
		t.Fatalf("mkdir launcher block dir: %v", err)
	}
	if err := os.WriteFile(launcherBlockPath, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("write launcher block file: %v", err)
	}
	if err := Run(context.Background(), []string{
		"app", "connect", "occupied",
		"--cmd", "true",
		"--install",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "not managed by hasp") {
		t.Fatalf("expected unmanaged launcher protection, got %v", err)
	}
	if err := Run(context.Background(), []string{
		"app", "connect", "../bad",
		"--cmd", "true",
	}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "invalid app name") {
		t.Fatalf("expected invalid app name failure, got %v", err)
	}

	var disconnectOut bytes.Buffer
	if err := Run(context.Background(), []string{"app", "disconnect", "myapp"}, bytes.NewBuffer(nil), &disconnectOut, &disconnectOut); err != nil {
		t.Fatalf("app disconnect: %v", err)
	}
	if _, err := os.Stat(launcherPath); !os.IsNotExist(err) {
		t.Fatalf("expected launcher removal, stat err=%v", err)
	}
	if err := Run(context.Background(), []string{"app", "run", "myapp"}, bytes.NewBuffer(nil), io.Discard, io.Discard); !errors.Is(err, store.ErrConsumerNotFound) {
		t.Fatalf("expected missing app consumer after disconnect, got %v", err)
	}

	auditData, err := os.ReadFile(filepath.Join(homeDir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(auditData), "consumer.app.connect") || !strings.Contains(string(auditData), "consumer.app.run") || !strings.Contains(string(auditData), "consumer.app.disconnect") {
		t.Fatalf("expected app consumer audit events, got %q", string(auditData))
	}
}

func TestAppConnectPromptsBeforeInstallingLauncher(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	if out, err := run("git", "-C", projectRoot, "init"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set API_TOKEN: %v", err)
	}

	origIsCharDevice := secretIsCharDeviceFn
	defer func() { secretIsCharDeviceFn = origIsCharDevice }()
	secretIsCharDeviceFn = func(*os.File) bool { return true }

	yesInput, err := os.CreateTemp(t.TempDir(), "prompt-yes")
	if err != nil {
		t.Fatalf("create yes prompt input: %v", err)
	}
	defer os.Remove(yesInput.Name())
	if _, err := yesInput.WriteString("y\n"); err != nil {
		t.Fatalf("seed yes prompt input: %v", err)
	}
	if _, err := yesInput.Seek(0, 0); err != nil {
		t.Fatalf("rewind yes prompt input: %v", err)
	}

	var yesOut bytes.Buffer
	if err := appConnectCommandWithInput(context.Background(), []string{
		"prompted-app",
		"--project-root", projectRoot,
		"--cmd", "true",
		"--env", "OPENAI_API_KEY=API_TOKEN",
	}, yesInput, &yesOut, &yesOut); err != nil {
		t.Fatalf("prompted app connect with yes: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault handle after yes prompt: %v", err)
	}
	consumer, err := handle.GetAppConsumer("prompted-app")
	if err != nil {
		t.Fatalf("get prompted consumer after yes: %v", err)
	}
	if consumer.LauncherPath == "" {
		t.Fatal("expected launcher path after yes prompt")
	}
	if _, err := os.Stat(consumer.LauncherPath); err != nil {
		t.Fatalf("expected launcher file after yes prompt: %v", err)
	}
	if !strings.Contains(yesOut.String(), "Install launcher command") {
		t.Fatalf("expected launcher prompt in output, got %q", yesOut.String())
	}

	noInput, err := os.CreateTemp(t.TempDir(), "prompt-no")
	if err != nil {
		t.Fatalf("create no prompt input: %v", err)
	}
	defer os.Remove(noInput.Name())
	if _, err := noInput.WriteString("n\n"); err != nil {
		t.Fatalf("seed no prompt input: %v", err)
	}
	if _, err := noInput.Seek(0, 0); err != nil {
		t.Fatalf("rewind no prompt input: %v", err)
	}

	var noOut bytes.Buffer
	if err := appConnectCommandWithInput(context.Background(), []string{
		"no-launcher-app",
		"--project-root", projectRoot,
		"--cmd", "true",
		"--env", "OPENAI_API_KEY=API_TOKEN",
	}, noInput, &noOut, &noOut); err != nil {
		t.Fatalf("prompted app connect with no: %v", err)
	}
	handle, err = openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault handle after no prompt: %v", err)
	}
	consumer, err = handle.GetAppConsumer("no-launcher-app")
	if err != nil {
		t.Fatalf("get prompted consumer after no: %v", err)
	}
	if consumer.LauncherPath != "" {
		t.Fatalf("expected empty launcher path after no prompt, got %q", consumer.LauncherPath)
	}
	if strings.Contains(noOut.String(), "rollback failed") {
		t.Fatalf("unexpected rollback noise in no prompt output: %q", noOut.String())
	}
}

func TestAppConnectPromptsForMissingFields(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set API_TOKEN: %v", err)
	}

	origIsCharDevice := secretIsCharDeviceFn
	defer func() { secretIsCharDeviceFn = origIsCharDevice }()
	secretIsCharDeviceFn = func(*os.File) bool { return true }

	inputFile, err := os.CreateTemp(t.TempDir(), "app-connect-prompt")
	if err != nil {
		t.Fatalf("create prompt file: %v", err)
	}
	defer os.Remove(inputFile.Name())
	if _, err := inputFile.WriteString("prompted-app\ntrue\ny\nAPI_TOKEN\nenv\nOPENAI_API_KEY\nn\nn\n"); err != nil {
		t.Fatalf("seed prompt file: %v", err)
	}
	if _, err := inputFile.Seek(0, 0); err != nil {
		t.Fatalf("rewind prompt file: %v", err)
	}

	var out bytes.Buffer
	if err := appConnectCommandWithInput(context.Background(), nil, inputFile, &out, &out); err != nil {
		t.Fatalf("app connect prompts for missing fields: %v", err)
	}
	handle, err := openVaultHandle(context.Background())
	if err != nil {
		t.Fatalf("open vault handle: %v", err)
	}
	consumer, err := handle.GetAppConsumer("prompted-app")
	if err != nil {
		t.Fatalf("get prompted app consumer: %v", err)
	}
	if consumer.Command[2] != `exec true "$@"` {
		t.Fatalf("unexpected prompted command %+v", consumer.Command)
	}
	if len(consumer.Bindings) != 1 || consumer.Bindings[0].Target != "OPENAI_API_KEY" {
		t.Fatalf("unexpected prompted bindings %+v", consumer.Bindings)
	}
	if consumer.LauncherPath != "" {
		t.Fatalf("expected no launcher when prompt answer is no, got %q", consumer.LauncherPath)
	}
}

func TestAppConnectCoverageBranches(t *testing.T) {
	lockAppSeams(t)

	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)
	t.Setenv("HASP_MASTER_PASSWORD", "correct horse battery staple")

	if err := Run(context.Background(), []string{"init"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("run init: %v", err)
	}
	if err := Run(context.Background(), []string{"set", "--name", "API_TOKEN", "--value", "abc123"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("set API_TOKEN: %v", err)
	}

	t.Run("connect usage rejects extra args", func(t *testing.T) {
		err := appConnectCommandWithInput(context.Background(), []string{"myapp", "--cmd", "true", "extra"}, nil, io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "usage: hasp app connect") {
			t.Fatalf("expected usage error, got %v", err)
		}
	})

	t.Run("interactive prompt failure propagates", func(t *testing.T) {
		origIsCharDevice := secretIsCharDeviceFn
		defer func() { secretIsCharDeviceFn = origIsCharDevice }()
		secretIsCharDeviceFn = func(*os.File) bool { return true }

		inputFile, err := os.CreateTemp(t.TempDir(), "app-connect-prompt-fail")
		if err != nil {
			t.Fatalf("create prompt file: %v", err)
		}
		defer os.Remove(inputFile.Name())

		writer := errWriter{err: errors.New("prompt fail")}
		err = appConnectCommandWithInput(context.Background(), nil, inputFile, writer, writer)
		if err == nil || !strings.Contains(err.Error(), "prompt fail") {
			t.Fatalf("expected prompt failure, got %v", err)
		}
	})
}

func TestAppConnectPromptMissingCoverageBranches(t *testing.T) {
	t.Run("file delivery branch", func(t *testing.T) {
		cfg := &appConnectConfig{Name: "fileapp", Command: "true"}
		if err := appConnectPromptMissing(newSetupPrompter(bytes.NewBufferString("\nAPI_TOKEN\nfile\nCERT_PATH\nn\n"), io.Discard), cfg); err != nil {
			t.Fatalf("file delivery prompt: %v", err)
		}
		if cfg.FileMappings["CERT_PATH"] != "API_TOKEN" {
			t.Fatalf("unexpected file mappings %+v", cfg.FileMappings)
		}
	})

	t.Run("dotenv delivery branch", func(t *testing.T) {
		cfg := &appConnectConfig{Name: "dotenvapp", Command: "true"}
		if err := appConnectPromptMissing(newSetupPrompter(bytes.NewBufferString("\nAPI_TOKEN\ndotenv\nOPENAI_API_KEY\nENV_FILE\nn\n"), io.Discard), cfg); err != nil {
			t.Fatalf("dotenv delivery prompt: %v", err)
		}
		if cfg.DotenvMappings["OPENAI_API_KEY"] != "API_TOKEN" {
			t.Fatalf("unexpected dotenv mappings %+v", cfg.DotenvMappings)
		}
		if cfg.DotenvEnv != "ENV_FILE" {
			t.Fatalf("unexpected dotenv env %q", cfg.DotenvEnv)
		}
	})

	t.Run("unsupported delivery errors", func(t *testing.T) {
		cfg := &appConnectConfig{Name: "badapp", Command: "true"}
		err := appConnectPromptMissing(newSetupPrompter(bytes.NewBufferString("\nAPI_TOKEN\nweird\n"), io.Discard), cfg)
		if err == nil || !strings.Contains(err.Error(), "unsupported delivery mode") {
			t.Fatalf("expected unsupported delivery error, got %v", err)
		}
	})

	t.Run("existing dotenv mapping prompts for env path", func(t *testing.T) {
		cfg := &appConnectConfig{
			Name:           "dotenvapp",
			Command:        "true",
			DotenvMappings: mappingFlag{"OPENAI_API_KEY": "API_TOKEN"},
		}
		if err := appConnectPromptMissing(newSetupPrompter(bytes.NewBufferString("HASP_DOTENV\n"), io.Discard), cfg); err != nil {
			t.Fatalf("dotenv env recovery prompt: %v", err)
		}
		if cfg.DotenvEnv != "HASP_DOTENV" {
			t.Fatalf("unexpected dotenv env %q", cfg.DotenvEnv)
		}
	})

	t.Run("existing dotenv mapping prompt failure", func(t *testing.T) {
		cfg := &appConnectConfig{
			Name:           "dotenvapp",
			Command:        "true",
			DotenvMappings: mappingFlag{"OPENAI_API_KEY": "API_TOKEN"},
		}
		err := appConnectPromptMissing(newSetupPrompter(setupErrReader{}, io.Discard), cfg)
		if err == nil || !strings.Contains(err.Error(), "read fail") {
			t.Fatalf("expected dotenv env prompt failure, got %v", err)
		}
	})

	t.Run("command prompt failure", func(t *testing.T) {
		cfg := &appConnectConfig{Name: "app"}
		err := appConnectPromptMissing(newSetupPrompter(setupErrReader{}, io.Discard), cfg)
		if err == nil || !strings.Contains(err.Error(), "read fail") {
			t.Fatalf("expected command prompt failure, got %v", err)
		}
	})

	t.Run("mapping prompt failures", func(t *testing.T) {
		cases := []struct {
			name  string
			input io.Reader
		}{
			{name: "add mapping prompt", input: setupErrReader{}},
			{name: "secret name prompt", input: io.MultiReader(strings.NewReader("\n"), setupErrReader{})},
			{name: "delivery prompt", input: io.MultiReader(strings.NewReader("\nAPI_TOKEN\n"), setupErrReader{})},
			{name: "env target prompt", input: io.MultiReader(strings.NewReader("\nAPI_TOKEN\nenv\n"), setupErrReader{})},
			{name: "file target prompt", input: io.MultiReader(strings.NewReader("\nAPI_TOKEN\nfile\n"), setupErrReader{})},
			{name: "dotenv target prompt", input: io.MultiReader(strings.NewReader("\nAPI_TOKEN\ndotenv\n"), setupErrReader{})},
			{name: "dotenv env prompt", input: io.MultiReader(strings.NewReader("\nAPI_TOKEN\ndotenv\nOPENAI_API_KEY\n"), setupErrReader{})},
			{name: "add another prompt", input: io.MultiReader(strings.NewReader("\nAPI_TOKEN\nenv\nOPENAI_API_KEY\n"), setupErrReader{})},
		}
		for _, tc := range cases {
			cfg := &appConnectConfig{Name: "app", Command: "true"}
			if err := appConnectPromptMissing(newSetupPrompter(tc.input, io.Discard), cfg); err == nil || !strings.Contains(err.Error(), "read fail") {
				t.Fatalf("%s: expected prompt failure, got %v", tc.name, err)
			}
		}
	})
}
