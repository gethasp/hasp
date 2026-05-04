package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/secretops"
	"github.com/gethasp/hasp/apps/server/internal/app/ttyutil"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// secretCommand is the root dispatcher for `hasp secret`. It delegates to
// secretops.SecretCommand using the seam-wired Deps from defaultSecretDeps().
func secretCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretops.SecretCommand(ctx, defaultSecretDeps(), args, stdin, stdout, stderr)
}

// The following shims keep the package-app function signatures intact so
// that existing tests (which call them directly) continue to work without
// modification. Each shim prepends its subcommand name and delegates to
// secretops.SecretCommand, which routes through the same seam vars.

func secretAddCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretops.SecretCommand(ctx, defaultSecretDeps(), append([]string{"add"}, args...), stdin, stdout, stderr)
}

func secretUpdateCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretops.SecretCommand(ctx, defaultSecretDeps(), append([]string{"update"}, args...), stdin, stdout, stderr)
}

func secretRotateCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretops.SecretCommand(ctx, defaultSecretDeps(), append([]string{"rotate"}, args...), stdin, stdout, stderr)
}

func secretDeleteCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretops.SecretCommand(ctx, defaultSecretDeps(), append([]string{"delete"}, args...), stdin, stdout, stderr)
}

func secretGetCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretops.SecretCommand(ctx, defaultSecretDeps(), append([]string{"get"}, args...), stdin, stdout, stderr)
}

func secretListCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return secretops.SecretCommand(ctx, defaultSecretDeps(), append([]string{"list"}, args...), nil, stdout, nil)
}

func secretExposeCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretops.SecretCommand(ctx, defaultSecretDeps(), append([]string{"expose"}, args...), stdin, stdout, stderr)
}

func secretHideCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return secretops.SecretCommand(ctx, defaultSecretDeps(), append([]string{"hide"}, args...), stdin, stdout, stderr)
}

// ---- Package-app helpers kept for backward compatibility with tests ----
//
// The following functions are called directly from existing tests in
// package app. They keep their original signatures and delegate to the
// same seam vars, so test overrides (e.g. secretGetwdFn, secretIsCharDeviceFn)
// still take effect.

func existingExposureReference(exposures []store.ItemExposure, projectRoot string) string {
	for _, exposure := range exposures {
		if exposure.ProjectRoot == projectRoot {
			return exposure.Reference
		}
	}
	return ""
}

func ensureProjectBindingExplicit(ctx context.Context, handle *store.Handle, projectRoot string) (store.Binding, []store.VisibleReference, bool, error) {
	binding, visible, err := resolveBindingViewAppFn(handle, ctx, projectRoot)
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	if binding.ID != "" {
		return binding, visible, false, nil
	}
	defaults, err := loadProjectDefaults()
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	root, err := appCanonicalProjectRootFn(ctx, projectRoot)
	if err != nil {
		return store.Binding{}, nil, false, err
	}
	if !pathLooksLikeGitRepo(root) {
		return store.Binding{}, nil, false, fmt.Errorf("project %q is not a git repo", projectRoot)
	}
	installHooks := defaults.AutoInstallHooks && pathLooksLikeGitRepo(root)
	if _, err := bindProject(ctx, handle, root, cloneAliasSet(binding.Aliases), defaults.DefaultPolicy, installHooks); err != nil {
		return store.Binding{}, nil, false, err
	}
	binding, visible, err = resolveBindingViewAppFn(handle, ctx, root)
	return binding, visible, true, err
}

func secretProjectContext(ctx context.Context, projectRoot string) (string, bool, error) {
	path := strings.TrimSpace(projectRoot)
	if path == "" {
		cwd, err := secretGetwdFn()
		if err != nil {
			return "", false, err
		}
		path = cwd
	}
	root, err := appCanonicalProjectRootFn(ctx, path)
	if err != nil {
		return "", false, err
	}
	return root, pathLooksLikeGitRepo(root), nil
}

func secretPromptIsInteractive(prompt *secretPrompt) bool {
	if prompt == nil {
		return false
	}
	file, ok := ttyutil.StdinFile(prompt.stdin)
	if !ok {
		return false
	}
	return secretIsCharDeviceFn(file)
}

// resolveSecretAddExpose decides whether `hasp secret add` should auto-bind.
// Kept in package app with original signature so tests can call it directly.
func resolveSecretAddExpose(ctx context.Context, inRepo, vaultOnly bool, mode string, prompt *secretPrompt) (bool, error) {
	if !inRepo {
		return false, nil
	}
	if vaultOnly {
		return false, nil
	}
	switch mode {
	case "always":
		return true, nil
	case "never":
		return false, nil
	case "ask":
		if globalFlagsFromContext(ctx).yes {
			return true, nil
		}
		if !secretPromptIsInteractive(prompt) {
			return false, errors.New("non-interactive secret add inside a repo refuses to silently auto-bind; pass --vault-only, --expose=never to skip the bind, or --expose=always to opt in")
		}
		answer, err := prompt.confirm("Bind new secrets to this repo automatically", true)
		if err != nil {
			return false, err
		}
		return answer, nil
	default:
		return false, fmt.Errorf("unknown --expose %q", mode)
	}
}

// parseDotEnvForDiff and renderSecretDiff live exclusively in
// secretops/list.go; the package-app copies were unused after the secret
// dispatcher migration and have been removed.
