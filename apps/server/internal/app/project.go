package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/hooks"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var installHooksFn = hooks.Install

type aliasFlags map[string]string

func (a *aliasFlags) String() string {
	if a == nil {
		return ""
	}
	blob, _ := json.Marshal(a)
	return string(blob)
}

func (a *aliasFlags) Set(value string) error {
	alias, item, ok := strings.Cut(value, "=")
	if !ok {
		return errors.New("aliases must be in alias=item form")
	}
	if *a == nil {
		*a = map[string]string{}
	}
	(*a)[strings.TrimSpace(alias)] = strings.TrimSpace(item)
	return nil
}

func projectCommand(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: hasp project <bind|status|unbind>")
	}
	switch args[0] {
	case "bind":
		return projectBindCommand(ctx, args[1:], stdout)
	case "status":
		return projectStatusCommand(ctx, args[1:], stdout)
	case "unbind":
		return projectUnbindCommand(ctx, args[1:], stdout)
	default:
		return fmt.Errorf("unknown project subcommand %q", args[0])
	}
}

func projectBindCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("project bind", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectRoot := fs.String("project-root", ".", "")
	defaultPolicy := fs.String("default-policy", string(store.PolicySession), "")
	installHooks := fs.Bool("hooks", true, "")
	var aliases aliasFlags
	fs.Var(&aliases, "alias", "alias=item")
	if err := fs.Parse(args); err != nil {
		return err
	}

	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	binding, err := bindProject(ctx, handle, *projectRoot, aliases, store.SecretPolicy(*defaultPolicy), *installHooks)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(binding)
}

func projectStatusCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("project status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectRoot := fs.String("project-root", ".", "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	binding, visible, err := handle.ResolveBindingView(ctx, *projectRoot)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]any{
		"binding": binding,
		"visible": visible,
	})
}

func projectUnbindCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("project unbind", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectRoot := fs.String("project-root", ".", "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	if err := handle.DeleteBinding(ctx, *projectRoot); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "unbound")
	return err
}

func bindProject(ctx context.Context, handle *store.Handle, projectRoot string, aliases map[string]string, defaultPolicy store.SecretPolicy, installHooks bool) (store.Binding, error) {
	binding, err := handle.UpsertBinding(ctx, projectRoot, aliases, defaultPolicy, installHooks)
	if err != nil {
		return store.Binding{}, err
	}
	if installHooks {
		if err := installHooksFn(projectRoot); err != nil {
			return store.Binding{}, err
		}
	}
	return binding, nil
}
