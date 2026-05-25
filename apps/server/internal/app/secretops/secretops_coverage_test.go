package secretops

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/cmddispatch"
	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type fakeSecretPrompt struct {
	lines      []string
	secrets    [][]byte
	confirms   []bool
	errLine    error
	errSecret  error
	errConfirm error
}

func (p *fakeSecretPrompt) Line(string) (string, error) {
	if p.errLine != nil {
		return "", p.errLine
	}
	if len(p.lines) == 0 {
		return "ALPHA", nil
	}
	out := p.lines[0]
	p.lines = p.lines[1:]
	return out, nil
}

func (p *fakeSecretPrompt) SecretValue(string) ([]byte, error) {
	if p.errSecret != nil {
		return nil, p.errSecret
	}
	if len(p.secrets) == 0 {
		return []byte("secret-value"), nil
	}
	out := p.secrets[0]
	p.secrets = p.secrets[1:]
	return out, nil
}

func (p *fakeSecretPrompt) Confirm(string, bool) (bool, error) {
	if p.errConfirm != nil {
		return false, p.errConfirm
	}
	if len(p.confirms) == 0 {
		return true, nil
	}
	out := p.confirms[0]
	p.confirms = p.confirms[1:]
	return out, nil
}

func (p *fakeSecretPrompt) Collision(string) (string, string, error) {
	return "replace", "", nil
}

func fullSecretDeps(t *testing.T) (Deps, map[string]store.Item) {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	items := map[string]store.Item{
		"ALPHA": {Name: "ALPHA", Kind: store.ItemKindKV, Value: []byte("secret-value"), CreatedAt: now, UpdatedAt: now},
		"BETA":  {Name: "BETA", Kind: store.ItemKindKV, Value: []byte("changed"), CreatedAt: now, UpdatedAt: now},
		"FILE":  {Name: "FILE", Kind: store.ItemKindFile, Value: []byte("file\n"), CreatedAt: now, UpdatedAt: now},
	}
	exposures := map[string][]store.ItemExposure{
		"ALPHA": {{ProjectRoot: "/repo", Reference: "ALIAS"}},
	}
	prompt := &fakeSecretPrompt{}
	deps := Deps{
		OpenVault: func(context.Context) (*store.Handle, error) { return &store.Handle{}, nil },
		ClipboardCopy: func([]byte) error {
			return nil
		},
		UpsertItem: func(_ *store.Handle, name string, kind store.ItemKind, value []byte, metadata store.ItemMetadata) (store.Item, error) {
			item := store.Item{Name: name, Kind: kind, Value: append([]byte(nil), value...), Metadata: metadata, CreatedAt: now, UpdatedAt: now}
			items[name] = item
			return item, nil
		},
		GetItem: func(_ *store.Handle, name string) (store.Item, error) {
			item, ok := items[name]
			if !ok {
				return store.Item{}, store.ErrItemNotFound
			}
			return item, nil
		},
		DeleteItem: func(_ *store.Handle, name string) error {
			if _, ok := items[name]; !ok {
				return store.ErrItemNotFound
			}
			delete(items, name)
			return nil
		},
		ListItems: func(*store.Handle) []store.Item {
			return []store.Item{items["ALPHA"], items["BETA"], items["FILE"]}
		},
		BindItemAlias: func(_ *store.Handle, _ context.Context, root string, name string) (string, error) {
			ref := "@" + name
			exposures[name] = append(exposures[name], store.ItemExposure{ProjectRoot: root, Reference: ref})
			return ref, nil
		},
		HideItemFromProject: func(_ *store.Handle, _ context.Context, root string, name string) ([]string, error) {
			if name == "BETA" {
				return nil, nil
			}
			return []string{"@" + name}, nil
		},
		ItemExposures: func(_ *store.Handle, name string) []store.ItemExposure {
			return exposures[name]
		},
		RevokeGrantsForItem: func(*store.Handle, string) (int, error) { return 2, nil },
		IsCharDevice:        func(*os.File) bool { return true },
		RevealIsTTY:         func(io.Writer) bool { return true },
		Getwd:               func() (string, error) { return "/repo", nil },
		CanonicalProjectRoot: func(context.Context, string) (string, error) {
			return "/repo", nil
		},
		ResolveBindingView: func(*store.Handle, context.Context, string) (store.Binding, []store.VisibleReference, error) {
			return store.Binding{CanonicalRoot: "/repo"}, []store.VisibleReference{{Alias: "ALIAS", ItemName: "ALPHA"}}, nil
		},
		NewSecretPrompt: func(io.Reader, io.Writer, io.Writer) Prompt { return prompt },
		EnforceSecretPlaintextPolicyInteractive: func(context.Context, *store.Handle, string, store.PlaintextAction, io.Reader, io.Writer) error {
			return nil
		},
		SecretProjectContext: func(context.Context, string) (string, bool, error) { return "/repo", true, nil },
		EnsureProjectBindingExplicit: func(context.Context, *store.Handle, string) (store.Binding, []store.VisibleReference, bool, error) {
			return store.Binding{CanonicalRoot: "/repo"}, nil, true, nil
		},
		NoteResolvedProjectRootIfImplicit: func(*flag.FlagSet, bool, string, io.Writer) {},
		GlobalFlagsYes:                    func(context.Context) bool { return true },
		GlobalFlagsJSON:                   func(context.Context) bool { return false },
		IsHelpArg:                         nil,
		PrintHelpTopic:                    nil,
		GlobalFlagsColorOptions:           func(context.Context, io.Writer) ui.ColorOptions { return ui.ColorOptions{} },
		ActorLabel:                        func() string { return "tester" },
		AppendAuditCLI:                    func(string, map[string]any) {},
		WriteJSONResponse: func(w io.Writer, payload any) error {
			_, err := fmt.Fprint(w, "json")
			return err
		},
		RenderJSONOrHuman: func(_ context.Context, stdout io.Writer, _ bool, _ any, human func(io.Writer) error) error {
			return human(stdout)
		},
		CLIPlural: func(n int, singular, plural string) string {
			if n == 1 {
				return singular
			}
			return plural
		},
		SecretGetJSONPayload: func(metadata secrettypes.MetadataView, copied bool, reveal bool, value []byte) map[string]any {
			return map[string]any{"name": metadata.Name, "copied": copied, "reveal": reveal, "value": string(value)}
		},
		RenderSecretMetadata: func(w io.Writer, metadata secrettypes.MetadataView, copied bool) error {
			_, err := fmt.Fprintf(w, "%s:%v", metadata.Name, copied)
			return err
		},
		RenderSecretMutations: func(w io.Writer, title string, lead string, values []secrettypes.MutationView, missing []string) error {
			_, err := fmt.Fprintf(w, "%s:%d:%d", title, len(values), len(missing))
			return err
		},
		RenderSecretListJSONOrHumanWithColor: func(_ context.Context, stdout io.Writer, _ bool, secrets []secrettypes.MetadataView, _ ui.ColorOptions) error {
			_, err := fmt.Fprintf(stdout, "list:%d", len(secrets))
			return err
		},
		RenderSecretSearchJSONOrHuman: func(_ context.Context, stdout io.Writer, _ bool, query string, total int, secrets []secrettypes.MetadataView, _ ui.ColorOptions) error {
			_, err := fmt.Fprintf(stdout, "search:%s:%d:%d", query, total, len(secrets))
			return err
		},
		ExpandUserPath: func(path string) (string, error) {
			return strings.Replace(path, "~", "/home/test", 1), nil
		},
		ResolveSecretAddCollision: func(_ *store.Handle, name string, value []byte, onConflict string, _ Prompt) (string, []byte, string, error) {
			if onConflict == "skip" {
				return name, value, "skipped", nil
			}
			return name, value, "created", nil
		},
		PromptIsInteractive: func(Prompt) bool { return true },
		NewNotFoundError: func(msg string, hint string) error {
			return errors.New(msg + ": " + hint)
		},
		NewFlagSet: flag.NewFlagSet,
	}
	return deps, items
}

func TestSecretCommandSuccessPaths(t *testing.T) {
	deps, _ := fullSecretDeps(t)
	ctx := context.Background()
	var out bytes.Buffer

	stdin := strings.NewReader("stdin-value\n")
	if err := SecretCommand(ctx, deps, []string{"add", "--from-stdin", "--expose=always", "STDIN"}, stdin, &out, io.Discard); err != nil {
		t.Fatalf("add stdin: %v", err)
	}
	if !strings.Contains(out.String(), "Secret add") {
		t.Fatalf("add output %q", out.String())
	}

	path := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(path, []byte("file-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := SecretCommand(ctx, deps, []string{"add", "--kind=file", "--from-file", path, "--expose=never", "FILEADD"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("add file: %v", err)
	}
	out.Reset()
	if err := SecretCommand(ctx, deps, []string{"add", "--expose=never", "PROMPTED"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("add prompted arg: %v", err)
	}

	successes := [][]string{
		{"update", "ALPHA"},
		{"rotate", "ALPHA"},
		{"get", "ALPHA"},
		{"show", "ALPHA"},
		{"reveal", "ALPHA", "--newline"},
		{"copy", "ALPHA"},
		{"delete", "BETA", "--yes"},
		{"list"},
		{"search", "AL"},
		{"expose", "ALPHA"},
		{"hide", "ALPHA"},
		{"hide", "BETA"},
		{"retrieve", "ALPHA", "--copy"},
	}
	for _, args := range successes {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			out.Reset()
			if err := SecretCommand(ctx, deps, args, strings.NewReader(""), &out, io.Discard); err != nil {
				t.Fatalf("SecretCommand(%v): %v", args, err)
			}
		})
	}

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("ALPHA=secret-value\nBETA=other\nEXTRA=x\nexport QUOTED=\"q\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := SecretCommand(ctx, deps, []string{"diff", envPath}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("diff: %v", err)
	}
	if !strings.Contains(out.String(), "Secret diff") {
		t.Fatalf("diff output %q", out.String())
	}
}

func TestSecretCommandFallbacksAndHelpers(t *testing.T) {
	deps, _ := fullSecretDeps(t)
	deps.NewFlagSet = nil
	deps.IsHelpArg = nil
	deps.PrintHelpTopic = nil
	if err := SecretCommand(context.Background(), deps, []string{"list"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("fallback flag set: %v", err)
	}
	var out bytes.Buffer
	if err := SecretCommand(context.Background(), deps, []string{"help"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("fallback help: %v", err)
	}
	if !strings.Contains(out.String(), "Usage: hasp secret") {
		t.Fatalf("fallback help output %q", out.String())
	}

	origPrintHelp := cmddispatch.PrintHelpTopicFn
	t.Cleanup(func() { cmddispatch.PrintHelpTopicFn = origPrintHelp })
	cmddispatch.PrintHelpTopicFn = func(w io.Writer, args []string) error {
		_, err := w.Write([]byte(strings.Join(args, "/")))
		return err
	}
	deps.PrintHelpTopic = nil
	out.Reset()
	if err := SecretCommand(context.Background(), deps, []string{"add", "--help"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("cmddispatch help: %v", err)
	}
	if out.String() != "secret/add" {
		t.Fatalf("cmddispatch help output %q", out.String())
	}

	getFS := flag.NewFlagSet("secret get", flag.ContinueOnError)
	getFS.Bool("reveal", false, "")
	getFS.Bool("newline", false, "")
	if got := reorderFlagsBeforePositionals(getFS, []string{"ALPHA", "--reveal", "--newline"}); strings.Join(got, " ") != "--reveal --newline ALPHA" {
		t.Fatalf("reorder = %v", got)
	}
	exposeFS := flag.NewFlagSet("secret expose", flag.ContinueOnError)
	exposeFS.String("project-root", "", "")
	exposeFS.Bool("json", false, "")
	if got := reorderFlagsBeforePositionals(exposeFS, []string{"ALPHA", "--project-root", "/repo", "--json"}); strings.Join(got, " ") != "--project-root /repo --json ALPHA" {
		t.Fatalf("reorder = %v", got)
	}
	if d := levenshtein("kitten", "sitting"); d != 3 {
		t.Fatalf("levenshtein = %d", d)
	}
	if d := levenshtein("", "abc"); d != 3 {
		t.Fatalf("levenshtein empty left = %d", d)
	}
	if d := levenshtein("abc", ""); d != 3 {
		t.Fatalf("levenshtein empty right = %d", d)
	}
	if typoThreshold(3) != 1 || typoThreshold(4) != 2 {
		t.Fatal("bad typo thresholds")
	}
	if match, ok := closestMatch("udpate", []string{"update"}); !ok || match != "update" {
		t.Fatalf("closest match = %q %v", match, ok)
	}
	if _, ok := closestMatch("zzzzzz", []string{"update"}); ok {
		t.Fatal("unexpected closest match")
	}
	if ref := existingExposureReference([]store.ItemExposure{{ProjectRoot: "/repo", Reference: "@A"}}, "/repo"); ref != "@A" {
		t.Fatalf("existing exposure = %q", ref)
	}
	if ref := existingExposureReference(nil, "/repo"); ref != "" {
		t.Fatalf("missing exposure = %q", ref)
	}
}

func TestSecretInputHelpers(t *testing.T) {
	deps, _ := fullSecretDeps(t)
	prompt := &fakeSecretPrompt{lines: []string{"A", "B"}, secrets: [][]byte{[]byte("a"), []byte("b")}, confirms: []bool{true, false}}
	inputs, err := secretAddInputs(deps, nil, prompt)
	if err != nil || len(inputs) != 2 {
		t.Fatalf("interactive add inputs len=%d err=%v", len(inputs), err)
	}
	prompt = &fakeSecretPrompt{lines: []string{""}}
	if _, err := secretAddInputs(deps, nil, prompt); err == nil {
		t.Fatal("expected empty interactive name error")
	}
	prompt = &fakeSecretPrompt{errLine: errors.New("line")}
	if _, err := secretAddInputs(deps, nil, prompt); err == nil {
		t.Fatal("expected line error")
	}
	prompt = &fakeSecretPrompt{errSecret: errors.New("secret")}
	if _, err := secretAddInputs(deps, []string{"A"}, prompt); err == nil {
		t.Fatal("expected secret error")
	}
	prompt = &fakeSecretPrompt{lines: []string{"A"}, errSecret: errors.New("secret")}
	if _, err := secretUpdateInputs(deps, nil, prompt); err == nil {
		t.Fatal("expected update secret error")
	}
	prompt = &fakeSecretPrompt{errLine: errors.New("line")}
	if _, err := secretUpdateInputs(deps, nil, prompt); err == nil {
		t.Fatal("expected update line error")
	}
	prompt = &fakeSecretPrompt{errConfirm: errors.New("confirm")}
	if _, err := secretAddInputs(deps, nil, prompt); err == nil {
		t.Fatal("expected confirm error")
	}
	prompt = &fakeSecretPrompt{}
	if _, err := secretInputsFromArgs(deps, []string{""}, prompt); err == nil {
		t.Fatal("expected empty arg name")
	}
	if _, err := secretInputsFromArgs(deps, []string{"A=value"}, prompt); err == nil {
		t.Fatal("expected argv value refusal")
	}
	if names, err := secretNameInputs([]string{" A "}, prompt, "Name"); err != nil || names[0] != "A" {
		t.Fatalf("names = %v err=%v", names, err)
	}
	if _, err := secretNameInputs([]string{""}, prompt, "Name"); err == nil {
		t.Fatal("expected empty name arg")
	}
	prompt = &fakeSecretPrompt{errLine: errors.New("line")}
	if _, err := secretNameInputs(nil, prompt, "Name"); err == nil {
		t.Fatal("expected name prompt line error")
	}
	prompt = &fakeSecretPrompt{lines: []string{""}}
	if _, err := secretNameInputs(nil, prompt, "Name"); err == nil {
		t.Fatal("expected blank name prompt error")
	}
}

func TestResolveSecretAddExposeBranches(t *testing.T) {
	deps, _ := fullSecretDeps(t)
	ctx := context.Background()
	prompt := &fakeSecretPrompt{}
	cases := []struct {
		name      string
		inRepo    bool
		vaultOnly bool
		mode      string
		want      bool
	}{
		{"outside repo", false, false, "always", false},
		{"vault only", true, true, "always", false},
		{"always", true, false, "always", true},
		{"never", true, false, "never", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSecretAddExpose(ctx, deps, tc.inRepo, tc.vaultOnly, tc.mode, prompt)
			if err != nil || got != tc.want {
				t.Fatalf("got %v err %v", got, err)
			}
		})
	}
	deps.GlobalFlagsYes = func(context.Context) bool { return false }
	deps.PromptIsInteractive = func(Prompt) bool { return true }
	prompt.confirms = []bool{false}
	if got, err := resolveSecretAddExpose(ctx, deps, true, false, "ask", prompt); err != nil || got {
		t.Fatalf("ask false got=%v err=%v", got, err)
	}
	deps.PromptIsInteractive = func(Prompt) bool { return false }
	if _, err := resolveSecretAddExpose(ctx, deps, true, false, "ask", prompt); err == nil {
		t.Fatal("expected non-interactive ask error")
	}
	if _, err := resolveSecretAddExpose(ctx, deps, true, false, "wat", prompt); err == nil {
		t.Fatal("expected bad expose mode")
	}
	prompt.errConfirm = errors.New("confirm")
	deps.PromptIsInteractive = func(Prompt) bool { return true }
	if _, err := resolveSecretAddExpose(ctx, deps, true, false, "ask", prompt); err == nil {
		t.Fatal("expected confirm error")
	}
}

func TestSecretCommandErrorBranches(t *testing.T) {
	ctx := context.Background()
	base, _ := fullSecretDeps(t)
	errFile := filepath.Join(t.TempDir(), "missing")
	cases := []struct {
		name string
		args []string
		in   string
		mut  func(*Deps)
	}{
		{"unknown typo", []string{"udpate"}, "", nil},
		{"unknown no typo", []string{"zzzzzz"}, "", nil},
		{"add parse", []string{"add", "--bad"}, "", nil},
		{"add bad kind", []string{"add", "--kind=nope", "A"}, "", nil},
		{"add stdin file conflict", []string{"add", "--from-stdin", "--from-file", errFile, "A"}, "", nil},
		{"add file kind missing source", []string{"add", "--kind=file", "A"}, "", nil},
		{"add bad expose", []string{"add", "--expose=bad", "A"}, "", nil},
		{"add vault only conflict", []string{"add", "--vault-only", "--expose=always", "A"}, "", nil},
		{"add expand project", []string{"add", "A"}, "", func(d *Deps) {
			d.ExpandUserPath = func(string) (string, error) { return "", errors.New("expand") }
		}},
		{"add expand file", []string{"add", "--from-file", "x", "A"}, "", func(d *Deps) {
			seen := 0
			d.ExpandUserPath = func(string) (string, error) {
				seen++
				if seen == 2 {
					return "", errors.New("expand-file")
				}
				return "", nil
			}
		}},
		{"add open", []string{"add", "--from-stdin", "A"}, "v", func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"add from file name count", []string{"add", "--from-file", errFile, "A", "B"}, "", nil},
		{"add from file read", []string{"add", "--from-file", errFile, "A"}, "", nil},
		{"add from stdin name count", []string{"add", "--from-stdin", "A", "B"}, "v", nil},
		{"add project context", []string{"add", "--from-stdin", "--expose=always", "A"}, "v", func(d *Deps) {
			d.SecretProjectContext = func(context.Context, string) (string, bool, error) { return "", false, errors.New("ctx") }
		}},
		{"add ensure binding", []string{"add", "--from-stdin", "--expose=always", "A"}, "v", func(d *Deps) {
			d.EnsureProjectBindingExplicit = func(context.Context, *store.Handle, string) (store.Binding, []store.VisibleReference, bool, error) {
				return store.Binding{}, nil, false, errors.New("bind")
			}
		}},
		{"add collision", []string{"add", "--from-stdin", "--expose=never", "A"}, "v", func(d *Deps) {
			d.ResolveSecretAddCollision = func(*store.Handle, string, []byte, string, Prompt) (string, []byte, string, error) {
				return "", nil, "", errors.New("collision")
			}
		}},
		{"add upsert", []string{"add", "--from-stdin", "--expose=never", "A"}, "v", func(d *Deps) {
			d.UpsertItem = func(*store.Handle, string, store.ItemKind, []byte, store.ItemMetadata) (store.Item, error) {
				return store.Item{}, errors.New("upsert")
			}
		}},
		{"add bind", []string{"add", "--from-stdin", "--expose=always", "A"}, "v", func(d *Deps) {
			d.BindItemAlias = func(*store.Handle, context.Context, string, string) (string, error) {
				return "", errors.New("alias")
			}
		}},
		{"add default input", []string{"add", "A=value"}, "", nil},
		{"update parse", []string{"update", "--bad"}, "", nil},
		{"update open", []string{"update", "A"}, "", func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"update get", []string{"update", "MISSING"}, "", nil},
		{"update upsert", []string{"update", "ALPHA"}, "", func(d *Deps) {
			d.UpsertItem = func(*store.Handle, string, store.ItemKind, []byte, store.ItemMetadata) (store.Item, error) {
				return store.Item{}, errors.New("upsert")
			}
		}},
		{"update input", []string{"update", "ALPHA=value"}, "", nil},
		{"rotate parse", []string{"rotate", "--bad"}, "", nil},
		{"rotate open", []string{"rotate", "ALPHA"}, "", func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"rotate get", []string{"rotate", "MISSING"}, "", nil},
		{"rotate upsert", []string{"rotate", "ALPHA"}, "", func(d *Deps) {
			d.UpsertItem = func(*store.Handle, string, store.ItemKind, []byte, store.ItemMetadata) (store.Item, error) {
				return store.Item{}, errors.New("upsert")
			}
		}},
		{"rotate revoke", []string{"rotate", "ALPHA"}, "", func(d *Deps) {
			d.RevokeGrantsForItem = func(*store.Handle, string) (int, error) { return 0, errors.New("revoke") }
		}},
		{"rotate input", []string{"rotate", "ALPHA=value"}, "", nil},
		{"get parse", []string{"get", "ALPHA", "--bad"}, "", nil},
		{"get show reveal conflict", []string{"show", "ALPHA", "--reveal"}, "", nil},
		{"get show copy conflict", []string{"show", "ALPHA", "--copy"}, "", nil},
		{"get reveal copy conflict", []string{"reveal", "ALPHA", "--copy"}, "", nil},
		{"get copy reveal conflict", []string{"copy", "ALPHA", "--reveal"}, "", nil},
		{"get both flags", []string{"get", "ALPHA", "--reveal", "--copy"}, "", nil},
		{"get open", []string{"get", "ALPHA"}, "", func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"get name count", []string{"get", "ALPHA", "BETA"}, "", nil},
		{"get name prompt", []string{"get"}, "", func(d *Deps) {
			d.NewSecretPrompt = func(io.Reader, io.Writer, io.Writer) Prompt { return &fakeSecretPrompt{errLine: errors.New("line")} }
		}},
		{"get missing", []string{"get", "MISSING"}, "", nil},
		{"get raw get error", []string{"get", "ALPHA"}, "", func(d *Deps) {
			d.GetItem = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get") }
		}},
		{"reveal policy", []string{"reveal", "ALPHA"}, "", func(d *Deps) {
			d.EnforceSecretPlaintextPolicyInteractive = func(context.Context, *store.Handle, string, store.PlaintextAction, io.Reader, io.Writer) error {
				return errors.New("policy")
			}
		}},
		{"copy policy", []string{"copy", "ALPHA"}, "", func(d *Deps) {
			d.EnforceSecretPlaintextPolicyInteractive = func(context.Context, *store.Handle, string, store.PlaintextAction, io.Reader, io.Writer) error {
				return errors.New("policy")
			}
		}},
		{"copy clipboard", []string{"copy", "ALPHA"}, "", func(d *Deps) {
			d.ClipboardCopy = func([]byte) error { return errors.New("clip") }
		}},
		{"delete parse", []string{"delete", "--bad"}, "", nil},
		{"delete open", []string{"delete", "ALPHA"}, "", func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"delete confirm", []string{"delete", "ALPHA"}, "", func(d *Deps) {
			d.GlobalFlagsYes = func(context.Context) bool { return false }
			d.NewSecretPrompt = func(io.Reader, io.Writer, io.Writer) Prompt {
				return &fakeSecretPrompt{errConfirm: errors.New("confirm")}
			}
		}},
		{"delete error", []string{"delete", "ALPHA", "--yes"}, "", func(d *Deps) {
			d.DeleteItem = func(*store.Handle, string) error { return errors.New("delete") }
		}},
		{"delete name prompt", []string{"delete"}, "", func(d *Deps) {
			d.NewSecretPrompt = func(io.Reader, io.Writer, io.Writer) Prompt { return &fakeSecretPrompt{errLine: errors.New("line")} }
		}},
		{"list parse", []string{"list", "--bad"}, "", nil},
		{"list open", []string{"list"}, "", func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"search parse", []string{"search", "--bad"}, "", nil},
		{"search usage no args", []string{"search"}, "", nil},
		{"search usage blank", []string{"search", " "}, "", nil},
		{"search open", []string{"search", "a"}, "", func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"diff parse", []string{"diff", "--bad"}, "", nil},
		{"diff usage no args", []string{"diff"}, "", nil},
		{"diff usage blank", []string{"diff", " "}, "", nil},
		{"diff read", []string{"diff", errFile}, "", nil},
		{"expose parse", []string{"expose", "--bad"}, "", nil},
		{"expose expand", []string{"expose", "ALPHA"}, "", func(d *Deps) {
			d.ExpandUserPath = func(string) (string, error) { return "", errors.New("expand") }
		}},
		{"expose open", []string{"expose", "ALPHA"}, "", func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"expose project", []string{"expose", "ALPHA"}, "", func(d *Deps) {
			d.SecretProjectContext = func(context.Context, string) (string, bool, error) { return "", false, errors.New("ctx") }
		}},
		{"expose not repo", []string{"expose", "ALPHA"}, "", func(d *Deps) {
			d.SecretProjectContext = func(context.Context, string) (string, bool, error) { return "", false, nil }
		}},
		{"expose ensure", []string{"expose", "ALPHA"}, "", func(d *Deps) {
			d.EnsureProjectBindingExplicit = func(context.Context, *store.Handle, string) (store.Binding, []store.VisibleReference, bool, error) {
				return store.Binding{}, nil, false, errors.New("bind")
			}
		}},
		{"expose get", []string{"expose", "MISSING"}, "", nil},
		{"expose name prompt", []string{"expose"}, "", func(d *Deps) {
			d.NewSecretPrompt = func(io.Reader, io.Writer, io.Writer) Prompt { return &fakeSecretPrompt{errLine: errors.New("line")} }
		}},
		{"expose bind", []string{"expose", "ALPHA"}, "", func(d *Deps) {
			d.BindItemAlias = func(*store.Handle, context.Context, string, string) (string, error) { return "", errors.New("alias") }
		}},
		{"hide parse", []string{"hide", "--bad"}, "", nil},
		{"hide expand", []string{"hide", "ALPHA"}, "", func(d *Deps) {
			d.ExpandUserPath = func(string) (string, error) { return "", errors.New("expand") }
		}},
		{"hide open", []string{"hide", "ALPHA"}, "", func(d *Deps) {
			d.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
		}},
		{"hide project", []string{"hide", "ALPHA"}, "", func(d *Deps) {
			d.SecretProjectContext = func(context.Context, string) (string, bool, error) { return "", false, errors.New("ctx") }
		}},
		{"hide not repo", []string{"hide", "ALPHA"}, "", func(d *Deps) {
			d.SecretProjectContext = func(context.Context, string) (string, bool, error) { return "", false, nil }
		}},
		{"hide item", []string{"hide", "ALPHA"}, "", func(d *Deps) {
			d.HideItemFromProject = func(*store.Handle, context.Context, string, string) ([]string, error) { return nil, errors.New("hide") }
		}},
		{"hide name prompt", []string{"hide"}, "", func(d *Deps) {
			d.NewSecretPrompt = func(io.Reader, io.Writer, io.Writer) Prompt { return &fakeSecretPrompt{errLine: errors.New("line")} }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := base
			if tc.mut != nil {
				tc.mut(&deps)
			}
			if err := SecretCommand(ctx, deps, tc.args, strings.NewReader(tc.in), io.Discard, io.Discard); err == nil {
				t.Fatalf("expected error for %v", tc.args)
			}
		})
	}
}

func TestSecretAdditionalBranches(t *testing.T) {
	ctx := context.Background()
	deps, _ := fullSecretDeps(t)
	var out bytes.Buffer
	if err := SecretCommand(ctx, deps, []string{"add", "--from-stdin", "BROKEN"}, errorReader{}, &out, io.Discard); err == nil {
		t.Fatal("expected add stdin read error")
	}
	deps.GlobalFlagsYes = func(context.Context) bool { return false }
	deps.PromptIsInteractive = func(Prompt) bool { return false }
	if err := SecretCommand(ctx, deps, []string{"add", "--from-stdin", "ASK"}, strings.NewReader("v"), &out, io.Discard); err == nil {
		t.Fatal("expected add expose ask error")
	}
	deps, items := fullSecretDeps(t)
	if err := SecretCommand(ctx, deps, []string{"add", "--from-stdin", "--on-conflict=skip", "--expose=never", "SKIP"}, strings.NewReader("v"), &out, io.Discard); err != nil {
		t.Fatalf("add skipped: %v", err)
	}
	if _, ok := items["SKIP"]; ok {
		t.Fatal("skipped item was persisted")
	}

	deps, _ = fullSecretDeps(t)
	deps.GlobalFlagsYes = func(context.Context) bool { return false }
	deps.NewSecretPrompt = func(io.Reader, io.Writer, io.Writer) Prompt {
		return &fakeSecretPrompt{confirms: []bool{false}}
	}
	out.Reset()
	if err := SecretCommand(ctx, deps, []string{"delete", "ALPHA"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("delete declined: %v", err)
	}

	deps, _ = fullSecretDeps(t)
	deps.RevealIsTTY = func(io.Writer) bool { return false }
	out.Reset()
	if err := SecretCommand(ctx, deps, []string{"reveal", "ALPHA"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("reveal no tty: %v", err)
	}
	out.Reset()
	if err := SecretCommand(ctx, deps, []string{"reveal", "ALPHA", "--no-newline"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("reveal no newline: %v", err)
	}
	deps.GlobalFlagsJSON = func(context.Context) bool { return true }
	out.Reset()
	if err := SecretCommand(ctx, deps, []string{"reveal", "ALPHA"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("reveal json: %v", err)
	}

	deps, _ = fullSecretDeps(t)
	if err := SecretCommand(ctx, deps, []string{"reveal", "ALPHA"}, strings.NewReader(""), errorWriter{}, io.Discard); err == nil {
		t.Fatal("expected reveal write error")
	}
	deps, _ = fullSecretDeps(t)
	if err := SecretCommand(ctx, deps, []string{"delete", "MISSING", "--yes"}, strings.NewReader(""), io.Discard, io.Discard); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	deps, _ = fullSecretDeps(t)
	if _, err := secretUpdateInputs(deps, nil, &fakeSecretPrompt{lines: []string{"PROMPTED"}, secrets: [][]byte{[]byte("v")}}); err != nil {
		t.Fatalf("secretUpdateInputs success: %v", err)
	}
	if names, err := secretNameInputs(nil, &fakeSecretPrompt{lines: []string{"PROMPTED"}}, "Name"); err != nil || names[0] != "PROMPTED" {
		t.Fatalf("secretNameInputs prompt = %v err=%v", names, err)
	}
	if _, err := secretAddInputs(deps, nil, &fakeSecretPrompt{lines: []string{"A"}, errSecret: errors.New("secret")}); err == nil {
		t.Fatal("expected interactive add secret error")
	}
	deps.GlobalFlagsYes = func(context.Context) bool { return true }
	if got, err := resolveSecretAddExpose(ctx, deps, true, false, "ask", &fakeSecretPrompt{}); err != nil || !got {
		t.Fatalf("ask global yes got=%v err=%v", got, err)
	}

	deps, _ = fullSecretDeps(t)
	diffPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(diffPath, []byte("\n# comment\nALPHA=secret-value\nBETA=other\nEXTRA=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := SecretCommand(ctx, deps, []string{"diff", diffPath}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("fresh diff: %v", err)
	}
	missingPath := filepath.Join(t.TempDir(), "missing.env")
	if err := os.WriteFile(missingPath, []byte("ALPHA=secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := SecretCommand(ctx, deps, []string{"diff", missingPath}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatalf("missing diff: %v", err)
	}
	deps, _ = fullSecretDeps(t)
	deps.OpenVault = func(context.Context) (*store.Handle, error) { return nil, errors.New("open") }
	if err := SecretCommand(ctx, deps, []string{"diff", diffPath}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected diff open error")
	}
	deps, _ = fullSecretDeps(t)
	deps.GetItem = func(*store.Handle, string) (store.Item, error) { return store.Item{}, errors.New("get") }
	if err := SecretCommand(ctx, deps, []string{"diff", diffPath}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected diff get error")
	}
	badEnvPath := filepath.Join(t.TempDir(), "bad.env")
	if err := os.WriteFile(badEnvPath, []byte("NOPE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps, _ = fullSecretDeps(t)
	if err := SecretCommand(ctx, deps, []string{"diff", badEnvPath}, strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Fatal("expected diff parse error")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read") }

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write") }

type secondWriteErrorWriter struct {
	writes int
}

func (w *secondWriteErrorWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > 1 {
		return 0, errors.New("write")
	}
	return len(p), nil
}

func TestSecretDotEnvAndRenderErrors(t *testing.T) {
	if _, err := parseDotEnvForDiff(strings.NewReader("NOPE\n")); err == nil {
		t.Fatal("expected invalid env line")
	}
	if got, err := parseDotEnvForDiff(strings.NewReader("\n# comment\nexport A=\"quoted\\\"\"\nB=plain'\nC='single quoted'\n")); err != nil || got["A"] != "quoted\"" || got["B"] != "plain'" || got["C"] != "single quoted" {
		t.Fatalf("parse dotenv got=%v err=%v", got, err)
	}
	if _, err := parseDotEnvForDiff(errorReader{}); err == nil {
		t.Fatal("expected scanner error")
	}
	if err := renderSecretDiff(errorWriter{}, "x", []string{"a"}, nil, nil, nil); err == nil {
		t.Fatal("expected header write error")
	}
	if err := renderSecretDiff(&secondWriteErrorWriter{}, "x", []string{"a"}, nil, nil, nil); err == nil {
		t.Fatal("expected row write error")
	}
	if err := renderSecretDiff(&bytes.Buffer{}, "x", []string{"a"}, []string{"b"}, []string{"c"}, []string{"d"}); err != nil {
		t.Fatalf("render diff: %v", err)
	}
}
