package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
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
	return projectCommandWithStderr(ctx, args, stdout, io.Discard)
}

func projectCommandWithStderr(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 || isHelpArg(args[0]) {
		return printHelpTopic(stdout, []string{"project"})
	}
	switch args[0] {
	case "adopt":
		return projectAdoptCommand(ctx, args[1:], stdout)
	case "bind":
		noteSetupCanonical(stderr, "hasp project bind")
		return projectBindCommand(ctx, args[1:], stdout)
	case "doctor":
		return projectManifestDoctorCommand(ctx, args[1:], stdout)
	case "examples":
		return projectExamplesCommand(ctx, args[1:], stdout)
	case "requirements":
		return projectRequirementsCommand(ctx, args[1:], stdout)
	case "status":
		return projectStatusCommand(ctx, args[1:], stdout)
	case "targets":
		return projectTargetsCommand(ctx, args[1:], stdout)
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
	Under        string                  `json:"under"`
	Preview      bool                    `json:"preview"`
	Defaults     projectDefaults         `json:"defaults"`
	Candidates   []projectAdoptCandidate `json:"candidates"`
	ScannedRoots int                     `json:"scanned_roots"`
	AdoptedCount int                     `json:"adopted_count"`
}

func projectAdoptCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("project adopt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	under := fs.String("under", ".", "")
	preview := fs.Bool("preview", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	expandedUnder, err := expandUserPath(strings.TrimSpace(*under))
	if err != nil {
		return fmt.Errorf("--under: %w", err)
	}
	*under = expandedUnder

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

	return renderJSONOrHuman(ctx, stdout, *jsonOutput, result, func(w io.Writer) error {
		return renderProjectAdoptResult(w, result)
	})
}

func projectBindCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("project bind", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", ".", "")
	defaultPolicy := fs.String("default-policy", string(store.PolicySession), "")
	installHooks := fs.Bool("hooks", true, "")
	allowNonGit := fs.Bool("allow-non-git", false, "")
	var aliases aliasFlags
	fs.Var(&aliases, "alias", "alias=item")
	if err := fs.Parse(args); err != nil {
		return err
	}

	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return err
	}

	// Invoke the canonical-root seam first so tests can intercept the resolved path.
	// We do not use the returned value here: UpsertBinding applies its own
	// CanonicalProjectPath logic (no git-root walk), which correctly preserves
	// sub-directory roots for monorepo bindings.
	if _, err := projectCanonicalRootFn(ctx, expandedRoot); err != nil {
		return err
	}

	// Validate that the path exists and is a directory.
	info, statErr := os.Stat(expandedRoot)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return fmt.Errorf("project root %q does not exist", expandedRoot)
		}
		return fmt.Errorf("project root %q: %w", expandedRoot, statErr)
	}
	if !info.IsDir() {
		return fmt.Errorf("project root %q is not a directory", expandedRoot)
	}

	// Require a git working tree unless --allow-non-git is set.
	if !*allowNonGit && !pathLooksLikeGitRepo(expandedRoot) {
		return fmt.Errorf("project root %q is not a git repository; pass --allow-non-git to bind anyway", expandedRoot)
	}

	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	binding, err := bindProject(ctx, handle, expandedRoot, aliases, store.SecretPolicy(*defaultPolicy), *installHooks)
	if err != nil {
		return err
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, binding, func(w io.Writer) error {
		return renderProjectBinding(w, "Project bound", "Bound the repository to HASP.", binding)
	})
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
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", ".", "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return fmt.Errorf("--project-root: %w", err)
	}
	*projectRoot = expandedRoot

	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	binding, visible, _, err := ensureProjectBinding(ctx, handle, *projectRoot)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"binding": binding,
		"visible": visible,
	}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderProjectStatus(w, binding, visible)
	})
}

func projectUnbindCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("project unbind", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	projectRoot := fs.String("project-root", ".", "")
	if err := fs.Parse(args); err != nil {
		return err
	}

	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return fmt.Errorf("--project-root: %w", err)
	}
	*projectRoot = expandedRoot

	handle, err := openVaultHandleFn(ctx)
	if err != nil {
		return err
	}
	if err := handle.DeleteBinding(ctx, *projectRoot); err != nil {
		return err
	}
	root, rootErr := projectCanonicalRootFn(ctx, *projectRoot)
	if rootErr != nil {
		root = *projectRoot
	}
	payload := map[string]any{"project_root": root, "outcome": "unbound"}
	return renderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSimpleAction(ctx, w, "Project unbound", "Removed the HASP binding for the repository.",
			cliPair("Project root", cliDisplayPath(root)),
			cliPair("Outcome", "unbound"),
		)
	})
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
