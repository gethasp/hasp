package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/projectcontext"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type projectDefaults = projectcontext.Defaults

var (
	loadCLIConfigAppFn      = paths.LoadConfig
	projectPathStatFn       = os.Stat
	resolveBindingViewAppFn = (*store.Handle).ResolveBindingView
)

func loadProjectDefaults() (projectDefaults, error) {
	cfg, err := loadCLIConfigAppFn()
	if err != nil {
		return projectDefaults{}, err
	}

	autoProtect := true
	if cfg.AutoProtectRepos != nil {
		autoProtect = *cfg.AutoProtectRepos
	}
	autoInstallHooks := true
	if cfg.AutoInstallHooks != nil {
		autoInstallHooks = *cfg.AutoInstallHooks
	}

	policy := store.PolicySession
	switch store.SecretPolicy(strings.TrimSpace(cfg.DefaultCapturePolicy)) {
	case store.PolicyAuto, store.PolicySession, store.PolicyAccess:
		policy = store.SecretPolicy(strings.TrimSpace(cfg.DefaultCapturePolicy))
	case "":
		policy = store.PolicySession
	}

	return projectDefaults{
		AutoProtectRepos: autoProtect,
		AutoInstallHooks: autoInstallHooks,
		DefaultPolicy:    policy,
	}, nil
}

func ensureProjectBinding(ctx context.Context, handle *store.Handle, projectRoot string) (store.Binding, []store.VisibleReference, bool, error) {
	return projectcontext.Ensure(ctx, handle, projectRoot, appProjectContextDeps())
}

func pathLooksLikeGitRepo(root string) bool {
	root = strings.TrimSpace(root)
	if root == "" {
		return false
	}
	info, err := projectPathStatFn(filepath.Join(root, ".git"))
	if err != nil {
		return false
	}
	return info.IsDir() || info.Mode().IsRegular()
}

func requireProjectBinding(binding store.Binding, projectRoot string) error {
	if binding.ID != "" {
		return nil
	}
	return fmt.Errorf("project %q is not managed yet; run inside a git repo with auto-protect enabled or bind it explicitly", projectRoot)
}

func autoAdoptEligible(projectRoot string, binding store.Binding) bool {
	return strings.TrimSpace(projectRoot) != "" && binding.ID == ""
}

func validateProjectScopedSetupOptions(opts setupOptions) error {
	if strings.TrimSpace(opts.Repo) == "" && (opts.BindImports || len(opts.BindItems) > 0 || len(opts.Aliases) > 0) {
		return errors.New("project-scoped setup options require --project-root")
	}
	return nil
}
