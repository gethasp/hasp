package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/mcp"
	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type stringListFlags []string

func (s *stringListFlags) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringListFlags) Set(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return errors.New("item name is required")
	}
	*s = append(*s, trimmed)
	return nil
}

type bootstrapTarget struct {
	Profile            profiles.Profile                 `json:"profile"`
	SupportTier        string                           `json:"support_tier"`
	CompatibilityLabel string                           `json:"compatibility_label"`
	FirstClass         bool                             `json:"first_class"`
	ReleaseGate        *profiles.ReleaseGate            `json:"release_gate,omitempty"`
	Proof              map[string]profiles.SupportCheck `json:"proof,omitempty"`
}

type bootstrapResult struct {
	SupportTier        string                           `json:"support_tier"`
	CompatibilityLabel string                           `json:"compatibility_label"`
	FirstClass         bool                             `json:"first_class"`
	Profile            profiles.Profile                 `json:"profile"`
	ReleaseGate        *profiles.ReleaseGate            `json:"release_gate,omitempty"`
	Proof              map[string]profiles.SupportCheck `json:"proof,omitempty"`
	ProjectRoot        string                           `json:"project_root"`
	InitState          string                           `json:"init_state"`
	HooksEnabled       bool                             `json:"hooks_enabled"`
	Binding            store.Binding                    `json:"binding"`
	Visible            []store.VisibleReference         `json:"visible"`
	BoundAliases       map[string]string                `json:"bound_aliases"`
	Imported           []store.ImportedItem             `json:"imported,omitempty"`
	ImportPreviews     []importPreview                  `json:"import_previews,omitempty"`
	Verification       map[string]any                   `json:"verification"`
	Notes              []string                         `json:"notes,omitempty"`
	NextSteps          []string                         `json:"next_steps"`
}

type bootstrapOptions struct {
	ProfileID          string
	ProjectRoot        string
	DefaultPolicy      store.SecretPolicy
	InstallHooks       bool
	Verify             bool
	JSONOutput         bool
	Aliases            aliasFlags
	BindItems          stringListFlags
	ImportPaths        stringListFlags
	BindImports        bool
	SkipPasswordPolicy bool
}

const genericDocsPath = "docs/agent-profiles/generic.md"

func bootstrapCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return bootstrapCommandWithInput(ctx, args, nil, stdout, bootstrapVerification)
}

func bootstrapCommandWithInput(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, verifyFn func(profiles.Profile, bool) (map[string]any, error)) error {
	return bootstrapCommandWithInputAndDeps(ctx, args, stdin, stdout, verifyFn, defaultBootstrapDeps())
}

func bootstrapCommandWithInputAndDeps(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, verifyFn func(profiles.Profile, bool) (map[string]any, error), deps bootstrapDeps) error {
	if len(args) > 0 {
		switch args[0] {
		case "profiles":
			return bootstrapProfilesCommand(ctx, args[1:], stdout)
		case "doctor":
			return bootstrapDoctorCommandWithDeps(ctx, args[1:], stdin, stdout, deps)
		case "generic":
			return bootstrapGenericCommandWithDeps(ctx, args[1:], stdin, stdout, verifyFn, deps)
		case "print-config":
			return bootstrapPrintConfigCommand(args[1:], stdout)
		}
	}

	opts, err := parseBootstrapOptions(args, false)
	if err != nil {
		return err
	}
	target, err := bootstrapProfileTarget(opts.ProfileID)
	if err != nil {
		return err
	}
	return executeBootstrap(ctx, target, opts, stdin, stdout, verifyFn, deps)
}

func bootstrapGenericCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, verifyFn func(profiles.Profile, bool) (map[string]any, error)) error {
	return bootstrapGenericCommandWithDeps(ctx, args, stdin, stdout, verifyFn, defaultBootstrapDeps())
}

func bootstrapGenericCommandWithDeps(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer, verifyFn func(profiles.Profile, bool) (map[string]any, error), deps bootstrapDeps) error {
	opts, err := parseBootstrapOptions(args, true)
	if err != nil {
		return err
	}
	return executeBootstrap(ctx, genericBootstrapTarget(), opts, stdin, stdout, verifyFn, deps)
}

func bootstrapCommandWith(ctx context.Context, args []string, stdout io.Writer, verifyFn func(profiles.Profile, bool) (map[string]any, error)) error {
	return bootstrapCommandWithInput(ctx, args, nil, stdout, verifyFn)
}

func parseBootstrapOptions(args []string, allowGeneric bool) (bootstrapOptions, error) {
	importPaths, filteredArgs, err := extractStringListFlag(args, "--import")
	if err != nil {
		return bootstrapOptions{}, err
	}
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	profileID := fs.String("profile", "", "")
	projectRoot := fs.String("project-root", ".", "")
	defaultPolicy := fs.String("default-policy", string(store.PolicySession), "")
	installHooks := fs.Bool("hooks", true, "")
	verify := fs.Bool("verify", true, "")
	bindImports := fs.Bool("bind-imports", false, "")
	skipPasswordPolicy := fs.Bool("skip-password-policy", false, "")
	var aliases aliasFlags
	var bindItems stringListFlags
	fs.Var(&aliases, "alias", "alias=item")
	fs.Var(&bindItems, "bind-item", "item")
	if err := fs.Parse(filteredArgs); err != nil {
		return bootstrapOptions{}, err
	}

	if !allowGeneric && strings.TrimSpace(*profileID) == "" {
		return bootstrapOptions{}, errors.New("usage: hasp bootstrap --profile <id> [--project-root <path>] [--alias alias=item] [--bind-item item] [--import path|->] [--bind-imports] [--default-policy auto|session|access] [--hooks=true|false] [--verify=true|false]")
	}
	if allowGeneric && strings.TrimSpace(*profileID) != "" {
		return bootstrapOptions{}, errors.New("generic bootstrap does not accept --profile")
	}

	expandedRoot, err := expandUserPath(strings.TrimSpace(*projectRoot))
	if err != nil {
		return bootstrapOptions{}, fmt.Errorf("--project-root: %w", err)
	}

	return bootstrapOptions{
		ProfileID:          *profileID,
		ProjectRoot:        expandedRoot,
		DefaultPolicy:      store.SecretPolicy(*defaultPolicy),
		InstallHooks:       *installHooks,
		Verify:             *verify,
		JSONOutput:         *jsonOutput,
		Aliases:            aliases,
		BindItems:          bindItems,
		ImportPaths:        importPaths,
		BindImports:        *bindImports,
		SkipPasswordPolicy: *skipPasswordPolicy,
	}, nil
}

func bootstrapProfileTarget(profileID string) (bootstrapTarget, error) {
	status, err := profiles.LoadSupportStatus(profileID)
	if err != nil {
		return bootstrapTarget{}, err
	}
	gate := status.ReleaseGate
	return bootstrapTarget{
		Profile:            status.Profile,
		SupportTier:        status.SupportTier,
		CompatibilityLabel: status.CompatibilityLabel,
		FirstClass:         status.FirstClass,
		ReleaseGate:        &gate,
		Proof:              status.Proof,
	}, nil
}

func genericBootstrapTarget() bootstrapTarget {
	return bootstrapTarget{
		Profile: profiles.Profile{
			ID:                   "generic",
			Name:                 "Generic Broker Path",
			Transport:            "mcp-stdio",
			Command:              []string{"hasp", "mcp"},
			ProjectBindingRecipe: "Bind the repo, use hasp mcp for stdio transport, and use brokered run/inject/write-env commands as needed.",
			ApprovalPath:         "Use the same daemon-backed project, session, or window grants as the CLI and first-class profiles.",
			SafeInjectPath:       "Use hasp run or hasp inject through the local broker.",
			WriteEnvPath:         "Use hasp write-env only with explicit human convenience approval.",
			DocsPath:             genericDocsPath,
		},
		SupportTier:        profiles.SupportTierGenericCompatible,
		CompatibilityLabel: profiles.CompatibilityLabelGeneric,
		FirstClass:         false,
		Proof: map[string]profiles.SupportCheck{
			"support_tier": {
				Status: "warn",
				Detail: "generic broker compatibility is supported, but it is not first-class profile support",
			},
			"docs": {
				Status: "pass",
				Detail: "generic broker guide documents the fallback CLI/MCP path",
			},
		},
	}
}

func bootstrapProfilesCommand(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("bootstrap profiles", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp bootstrap profiles [--json]")
	}
	return bootstrapProfilesCommandWithMode(ctx, stdout, *jsonOutput, profiles.LoadCatalog, profiles.LoadReleaseGates)
}

func bootstrapProfilesCommandWith(stdout io.Writer, loadCatalog func() ([]profiles.Profile, error), loadGates func() (profiles.ReleaseGateManifest, error)) error {
	return bootstrapProfilesCommandWithMode(context.Background(), stdout, false, loadCatalog, loadGates)
}

func bootstrapProfilesCommandWithMode(ctx context.Context, stdout io.Writer, jsonOutput bool, loadCatalog func() ([]profiles.Profile, error), loadGates func() (profiles.ReleaseGateManifest, error)) error {
	result, err := bootstrapProfileListing(loadCatalog, loadGates)
	if err != nil {
		return err
	}
	return renderBootstrapProfileListingMaybeHuman(ctx, stdout, jsonOutput, result)
}

func bootstrapProfileListing(loadCatalog func() ([]profiles.Profile, error), loadGates func() (profiles.ReleaseGateManifest, error)) (map[string]any, error) {
	catalog, err := loadCatalog()
	if err != nil {
		return nil, err
	}
	manifest, err := loadGates()
	if err != nil {
		return nil, err
	}

	listing := make([]map[string]any, 0, len(catalog))
	for _, profile := range catalog {
		gate := manifest.Profiles[profile.ID]
		status := profiles.ContractStatusForProfile(profile, gate, manifest.RequiredDocSections)
		supportTier := profiles.SupportTierFirstClassShipped
		compatibilityLabel := profiles.CompatibilityLabelFirstClass
		if !status.Ready {
			supportTier = profiles.SupportTierGenericCompatible
			compatibilityLabel = profiles.CompatibilityLabelGeneric
		}
		listing = append(listing, map[string]any{
			"id":                  profile.ID,
			"name":                profile.Name,
			"support_tier":        supportTier,
			"compatibility_label": compatibilityLabel,
			"first_class":         status.Ready,
			"transport":           profile.Transport,
			"command":             profile.Command,
			"project_binding":     profile.ProjectBindingRecipe,
			"approval_path":       profile.ApprovalPath,
			"safe_inject_path":    profile.SafeInjectPath,
			"write_env_path":      profile.WriteEnvPath,
			"regression_fixture":  profile.RegressionFixture,
			"docs_path":           profile.DocsPath,
			"release_gate":        gate,
			"proof":               status,
			"doctor_command":      "hasp bootstrap doctor --profile " + profile.ID + " --project-root <repo>",
		})
	}
	sort.Slice(listing, func(i, j int) bool {
		return listing[i]["id"].(string) < listing[j]["id"].(string)
	})
	return map[string]any{
		"required_doc_sections": manifest.RequiredDocSections,
		"profiles":              listing,
		"generic_path":          genericCompatibilitySurface(),
		"convenience_mode":      convenienceModeSurface(),
	}, nil
}

func executeBootstrap(ctx context.Context, target bootstrapTarget, opts bootstrapOptions, stdin io.Reader, stdout io.Writer, verifyFn func(profiles.Profile, bool) (map[string]any, error), deps bootstrapDeps) error {
	vaultStore, err := newVaultStoreFn()
	if err != nil {
		return err
	}
	handle, initState, err := ensureBootstrapHandle(ctx, vaultStore, opts.SkipPasswordPolicy)
	if err != nil {
		return err
	}
	if _, err := bindProject(ctx, handle, opts.ProjectRoot, opts.Aliases, opts.DefaultPolicy, opts.InstallHooks); err != nil {
		return err
	}
	var visible []store.VisibleReference
	binding, _, err := deps.ResolveBindingView(handle, ctx, opts.ProjectRoot)
	if err != nil {
		return err
	}

	importPreviews, imported, binding, _, err := applyBootstrapImports(ctx, handle, opts, binding, stdin, deps)
	if err != nil {
		return err
	}
	boundAliases, err := bindBootstrapItems(ctx, handle, opts.ProjectRoot, binding.Aliases, opts.BindItems)
	if err != nil {
		return err
	}
	binding, visible, err = deps.ResolveBindingView(handle, ctx, opts.ProjectRoot)
	if err != nil {
		return err
	}
	verification, err := verifyFn(target.Profile, opts.Verify)
	if err != nil {
		return err
	}

	result := bootstrapResult{
		SupportTier:        target.SupportTier,
		CompatibilityLabel: target.CompatibilityLabel,
		FirstClass:         target.FirstClass,
		Profile:            target.Profile,
		ReleaseGate:        target.ReleaseGate,
		Proof:              target.Proof,
		ProjectRoot:        opts.ProjectRoot,
		InitState:          initState,
		HooksEnabled:       opts.InstallHooks,
		Binding:            binding,
		Visible:            visible,
		BoundAliases:       mergeImportedAliases(boundAliases, imported),
		Imported:           imported,
		ImportPreviews:     importPreviews,
		Verification:       verification,
		Notes:              bootstrapNotes(target, opts, len(imported) > 0),
		NextSteps:          bootstrapNextSteps(target.Profile),
	}
	return renderBootstrapJSONOrHuman(ctx, stdout, opts.JSONOutput, result)
}

func applyBootstrapImports(ctx context.Context, handle *store.Handle, opts bootstrapOptions, binding store.Binding, stdin io.Reader, deps bootstrapDeps) ([]importPreview, []store.ImportedItem, store.Binding, []store.VisibleReference, error) {
	if len(opts.ImportPaths) == 0 {
		return nil, nil, binding, nil, nil
	}

	currentAliases := cloneAliasSet(binding.Aliases)
	previews := make([]importPreview, 0, len(opts.ImportPaths))
	imported := []store.ImportedItem{}
	for _, importPath := range opts.ImportPaths {
		prepared, err := prepareImport(importPath, "auto", "", stdin, opts.BindImports, currentAliases)
		if err != nil {
			return nil, nil, binding, nil, err
		}
		previews = append(previews, prepared.Preview)
		result, err := handle.ImportPath(ctx, prepared.Path, store.ImportOptions{
			ProjectRoot:   opts.ProjectRoot,
			BindToProject: opts.BindImports,
		})
		prepared.Cleanup()
		if err != nil {
			return nil, nil, binding, nil, err
		}
		imported = append(imported, result.Imported...)
		for _, item := range result.Imported {
			if item.Alias != "" {
				currentAliases[item.Alias] = item.Name
			}
		}
		binding.Aliases = currentAliases
	}
	updatedBinding, visible, err := deps.ResolveBindingView(handle, ctx, opts.ProjectRoot)
	if err != nil {
		return nil, nil, binding, nil, err
	}
	return previews, imported, updatedBinding, visible, nil
}

func bindBootstrapItems(ctx context.Context, handle *store.Handle, projectRoot string, aliases map[string]string, bindItems []string) (map[string]string, error) {
	bound := map[string]string{}
	currentAliases := cloneAliasSet(aliases)
	for _, itemName := range bindItems {
		alias, err := handle.BindItemAlias(ctx, projectRoot, itemName)
		if err != nil {
			return nil, err
		}
		bound[alias] = itemName
		currentAliases[alias] = itemName
	}
	return bound, nil
}

func ensureBootstrapHandle(ctx context.Context, vaultStore *store.Store, skipPasswordPolicy bool) (*store.Handle, string, error) {
	handle, err := openVaultHandleFn(ctx)
	if err == nil {
		return handle, "existing", nil
	}
	if !errors.Is(err, store.ErrVaultNotInitialized) {
		return nil, "", err
	}
	password, err := loadMasterPassword()
	if err != nil {
		return nil, "", fmt.Errorf("vault not initialized; set HASP_MASTER_PASSWORD to let bootstrap initialize it")
	}
	if !skipPasswordPolicy {
		if err := store.EnforcePasswordPolicy(password); err != nil {
			return nil, "", err
		}
	}
	if err := vaultStore.Init(ctx, password); err != nil {
		return nil, "", err
	}
	handle, err = openStoreWithPasswordFn(ctx, vaultStore, password)
	if err != nil {
		return nil, "", err
	}
	return handle, "created", nil
}

func loadBootstrapProfile(profileID string, loadProfile func(string) (profiles.Profile, error), loadGate func(string) (profiles.ReleaseGate, error)) (profiles.Profile, profiles.ReleaseGate, error) {
	profile, err := loadProfile(profileID)
	if err != nil {
		return profiles.Profile{}, profiles.ReleaseGate{}, err
	}
	releaseGate, err := loadGate(profileID)
	if err != nil {
		return profiles.Profile{}, profiles.ReleaseGate{}, err
	}
	return profile, releaseGate, nil
}

func bootstrapVerification(profile profiles.Profile, verify bool) (map[string]any, error) {
	return bootstrapVerificationWith(profile, verify, mcp.ToolNames)
}

func bootstrapVerificationWith(profile profiles.Profile, verify bool, toolNamesFn func() []string) (map[string]any, error) {
	result := map[string]any{
		"enabled": verify,
		"surface": strings.Join(profile.Command, " "),
		"ready":   false,
	}
	if !verify {
		return result, nil
	}
	if len(profile.Command) == 2 && profile.Command[0] == "hasp" && profile.Command[1] == "mcp" {
		toolNames := toolNamesFn()
		if len(toolNames) == 0 {
			return nil, fmt.Errorf("bootstrap verification failed: MCP tool catalog is empty")
		}
		result["ready"] = true
		result["tools"] = toolNames
		result["transport_check"] = "shipped MCP tool catalog is available for the declared profile transport"
		return result, nil
	}
	result["ready"] = len(profile.Command) > 0
	result["transport_check"] = "profile command is declared"
	return result, nil
}

func bootstrapNotes(target bootstrapTarget, opts bootstrapOptions, usedImports bool) []string {
	notes := []string{}
	if !target.FirstClass {
		notes = append(notes, "this path is generic compatibility, not first-class profile support")
	}
	if usedImports {
		notes = append(notes, "local import remains an explicit human CLI capture path and does not materialize repo-visible secret files by default")
	}
	notes = append(notes, "V1 reduces common local leaks, not malicious same-user local process access")
	if opts.BindImports {
		notes = append(notes, "imported items are only auto-bound because --bind-imports was explicitly requested")
	}
	return notes
}

func bootstrapNextSteps(profile profiles.Profile) []string {
	next := []string{
		"start the profile transport with: " + strings.Join(profile.Command, " "),
		"profile binding recipe: " + profile.ProjectBindingRecipe,
		"approval path: " + profile.ApprovalPath,
		"safe path: " + profile.SafeInjectPath,
		"convenience path: " + profile.WriteEnvPath,
	}
	if profile.DocsPath != "" {
		next = append(next, "docs: "+profile.DocsPath)
	}
	return next
}

func mergeImportedAliases(boundAliases map[string]string, imported []store.ImportedItem) map[string]string {
	merged := cloneAliasSet(boundAliases)
	for _, item := range imported {
		if item.Alias != "" {
			merged[item.Alias] = item.Name
		}
	}
	return merged
}

func extractStringListFlag(args []string, name string) (stringListFlags, []string, error) {
	values := stringListFlags{}
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		current := args[i]
		if current == name {
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("%s requires a value", name)
			}
			values = append(values, args[i+1])
			i++
			continue
		}
		if strings.HasPrefix(current, name+"=") {
			values = append(values, strings.TrimPrefix(current, name+"="))
			continue
		}
		filtered = append(filtered, current)
	}
	return values, filtered, nil
}

func summarizeImportPreview(preview importPreview) map[string]any {
	kinds := map[string]int{}
	for _, change := range preview.PlannedChanges {
		kinds[string(change.Kind)]++
	}
	source := preview.Source
	if source != "stdin" {
		source = "local-file"
	}
	return map[string]any{
		"source":               source,
		"format":               preview.Format,
		"capture_mode_label":   preview.CaptureModeLabel,
		"bind_to_project":      preview.BindToProject,
		"planned_change_count": len(preview.PlannedChanges),
		"kinds":                kinds,
	}
}
