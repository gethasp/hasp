package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/hooks"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var installHooksFn = hooks.Install
var projectWalkDirFn = filepath.WalkDir
var projectCanonicalRootFn = store.CanonicalProjectRoot

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
		return errors.New("usage: hasp project <adopt|bind|status|unbind>")
	}
	switch args[0] {
	case "adopt":
		return projectAdoptCommand(ctx, args[1:], stdout)
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

type projectAdoptCandidate struct {
	ProjectRoot    string             `json:"project_root"`
	AlreadyManaged bool               `json:"already_managed"`
	Adopted        bool               `json:"adopted"`
	HooksEnabled   bool               `json:"hooks_enabled"`
	DefaultPolicy  store.SecretPolicy `json:"default_policy"`
	Reason         string             `json:"reason"`
}

type projectAdoptResult struct {
	Under        string                 `json:"under"`
	Preview      bool                   `json:"preview"`
	Defaults     projectDefaults        `json:"defaults"`
	Candidates   []projectAdoptCandidate `json:"candidates"`
	ScannedRoots int                    `json:"scanned_roots"`
	AdoptedCount int                    `json:"adopted_count"`
}

func projectAdoptCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("project adopt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	under := fs.String("under", ".", "")
	preview := fs.Bool("preview", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	defaults, err := loadProjectDefaults()
	if err != nil {
		return err
	}

	candidateRoots, err := discoverProjectRoots(ctx, *under)
	if err != nil {
		return err
	}
	result := projectAdoptResult{
		Under:        *under,
		Preview:      *preview,
		Defaults:     defaults,
		Candidates:   make([]projectAdoptCandidate, 0, len(candidateRoots)),
		ScannedRoots: len(candidateRoots),
	}

	for _, root := range candidateRoots {
		binding, _, err := handle.ResolveBindingView(ctx, root)
		if err != nil {
			return err
		}
		candidate := projectAdoptCandidate{
			ProjectRoot:    root,
			AlreadyManaged: strings.TrimSpace(binding.ID) != "",
			HooksEnabled:   defaults.AutoInstallHooks && pathLooksLikeGitRepo(root),
			DefaultPolicy:  defaults.DefaultPolicy,
		}
		if candidate.AlreadyManaged {
			candidate.Reason = "already managed"
			result.Candidates = append(result.Candidates, candidate)
			continue
		}
		if *preview {
			candidate.Reason = "would adopt"
			result.Candidates = append(result.Candidates, candidate)
			continue
		}
		if _, err := bindProject(ctx, handle, root, nil, defaults.DefaultPolicy, candidate.HooksEnabled); err != nil {
			return err
		}
		candidate.Adopted = true
		candidate.Reason = "adopted"
		result.AdoptedCount++
		result.Candidates = append(result.Candidates, candidate)
	}

	return json.NewEncoder(stdout).Encode(result)
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

func discoverProjectRoots(ctx context.Context, under string) ([]string, error) {
	root, err := projectCanonicalRootFn(ctx, under)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	roots := make([]string, 0)
	err = projectWalkDirFn(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Name() == ".git" {
			candidate := filepath.Dir(path)
			canonical, err := projectCanonicalRootFn(ctx, candidate)
			if err != nil {
				return err
			}
			if _, ok := seen[canonical]; !ok {
				seen[canonical] = struct{}{}
				roots = append(roots, canonical)
			}
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(roots)
	return roots, nil
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
	binding, visible, _, err := ensureProjectBinding(ctx, handle, *projectRoot)
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
