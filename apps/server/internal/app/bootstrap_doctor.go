package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/profiles"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type bootstrapDoctorResult struct {
	SupportTier          string                           `json:"support_tier"`
	CompatibilityLabel   string                           `json:"compatibility_label"`
	FirstClass           bool                             `json:"first_class"`
	Profile              profiles.Profile                 `json:"profile"`
	ReleaseGate          *profiles.ReleaseGate            `json:"release_gate,omitempty"`
	Proof                map[string]profiles.SupportCheck `json:"proof,omitempty"`
	Checks               map[string]profiles.SupportCheck `json:"checks"`
	ProjectRoot          string                           `json:"project_root"`
	ProjectCanonicalRoot string                           `json:"project_canonical_root"`
	VaultStatus          string                           `json:"vault_status"`
	HooksRequested       bool                             `json:"hooks_requested"`
	HooksPresent         bool                             `json:"hooks_present"`
	ExistingBinding      store.Binding                    `json:"existing_binding"`
	ExistingVisible      []store.VisibleReference         `json:"existing_visible"`
	PlannedImportSummary []map[string]any                 `json:"planned_import_summary,omitempty"`
	PlannedImports       []map[string]any                 `json:"planned_imports,omitempty"`
	PlannedBindCount     int                              `json:"planned_bind_count,omitempty"`
	GenericPath          map[string]any                   `json:"generic_path"`
	ConvenienceMode      map[string]any                   `json:"convenience_mode"`
	Transport            map[string]any                   `json:"transport"`
	Notes                []string                         `json:"notes,omitempty"`
}

var bootstrapCanonicalProjectRootFn = store.CanonicalProjectRoot
var resolveBindingViewBootstrapFn = (*store.Handle).ResolveBindingView

func bootstrapDoctorCommand(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	useGeneric := false
	if len(args) > 0 && args[0] == "generic" {
		useGeneric = true
		args = args[1:]
	}
	opts, err := parseBootstrapOptions(args, useGeneric)
	if err != nil {
		return err
	}

	target := genericBootstrapTarget()
	if !useGeneric {
		target, err = bootstrapProfileTarget(opts.ProfileID)
		if err != nil {
			return err
		}
	}

	report, err := buildBootstrapDoctor(ctx, target, opts, stdin)
	if err != nil {
		return err
	}
	return renderBootstrapDoctorJSONOrHuman(stdout, opts.JSONOutput, report)
}

func buildBootstrapDoctor(ctx context.Context, target bootstrapTarget, opts bootstrapOptions, stdin io.Reader) (bootstrapDoctorResult, error) {
	projectCanonicalRoot, err := bootstrapCanonicalProjectRootFn(ctx, opts.ProjectRoot)
	if err != nil {
		return bootstrapDoctorResult{}, err
	}

	handle, vaultStatus, err := previewBootstrapHandle(ctx)
	if err != nil {
		return bootstrapDoctorResult{}, err
	}

	report := bootstrapDoctorResult{
		SupportTier:          target.SupportTier,
		CompatibilityLabel:   target.CompatibilityLabel,
		FirstClass:           target.FirstClass,
		Profile:              target.Profile,
		ReleaseGate:          target.ReleaseGate,
		Proof:                target.Proof,
		Checks:               map[string]profiles.SupportCheck{},
		ProjectRoot:          opts.ProjectRoot,
		ProjectCanonicalRoot: projectCanonicalRoot,
		VaultStatus:          vaultStatus,
		HooksRequested:       opts.InstallHooks,
		HooksPresent:         bootstrapHookPresent(projectCanonicalRoot),
		GenericPath:          genericCompatibilitySurface(),
		ConvenienceMode:      convenienceModeSurface(),
		Transport: map[string]any{
			"command":                        target.Profile.Command,
			"declared":                       len(target.Profile.Command) > 0,
			"operator_confirmation_required": true,
			"detail":                         "doctor checks local broker state and shipped profile proof; external agent configuration remains operator-confirmed",
		},
		Notes: bootstrapNotes(target, opts, len(opts.ImportPaths) > 0),
	}
	report.Checks["project_root"] = profiles.SupportCheck{
		Status: "pass",
		Detail: "project root resolves locally",
	}
	if os.Getenv("HASP_MASTER_PASSWORD") == "" {
		report.Checks["master_password"] = profiles.SupportCheck{
			Status:   "fail",
			Detail:   "HASP_MASTER_PASSWORD is required for this command",
			Recovery: "set HASP_MASTER_PASSWORD before running local vault commands",
		}
	} else {
		report.Checks["master_password"] = profiles.SupportCheck{
			Status: "pass",
			Detail: "master password is present for local vault operations",
		}
	}
	report.Checks["vault"] = profiles.SupportCheck{
		Status: "pass",
		Detail: "vault status: " + vaultStatus,
	}
	if target.ReleaseGate != nil {
		report.Checks["release_gate"] = summarizeProof(target.Proof)
	}
	report.Checks["hooks"] = profiles.SupportCheck{
		Status: "pass",
		Detail: fmt.Sprintf("hooks requested=%t present=%t", report.HooksRequested, report.HooksPresent),
	}

	currentAliases := map[string]string{}
	if handle == nil {
		report.Notes = append(report.Notes, "vault is not initialized yet; doctor preview shows projected changes only")
		report.Checks["binding_view"] = profiles.SupportCheck{
			Status: "skip",
			Detail: "binding view is unavailable until the local vault is initialized",
		}
	} else {
		binding, visible, err := resolveBindingViewBootstrapFn(handle, ctx, opts.ProjectRoot)
		if err != nil {
			return bootstrapDoctorResult{}, err
		}
		report.ExistingBinding = binding
		report.ExistingVisible = visible
		report.Checks["binding_view"] = profiles.SupportCheck{
			Status: "pass",
			Detail: fmt.Sprintf("binding view resolves with %d visible aliases", len(visible)),
		}
		currentAliases = cloneAliasSet(binding.Aliases)
	}

	for _, importPath := range opts.ImportPaths {
		prepared, err := prepareImport(importPath, "auto", "", stdin, opts.BindImports, currentAliases)
		if err != nil {
			return bootstrapDoctorResult{}, err
		}
		summary := summarizeImportPreview(prepared.Preview)
		report.PlannedImports = append(report.PlannedImports, summary)
		report.PlannedImportSummary = append(report.PlannedImportSummary, summary)
		for _, item := range prepared.Preview.PlannedChanges {
			if item.Alias != "" {
				currentAliases[item.Alias] = item.Name
			}
		}
		prepared.Cleanup()
	}
	if len(report.PlannedImportSummary) > 0 {
		report.Checks["import_source"] = profiles.SupportCheck{
			Status: "pass",
			Detail: fmt.Sprintf("doctor parsed %d local import sources without exposing values", len(report.PlannedImportSummary)),
		}
	}
	for _, itemName := range opts.BindItems {
		if handle != nil {
			if _, err := handle.GetItem(itemName); err != nil {
				return bootstrapDoctorResult{}, err
			}
		}
		report.PlannedBindCount++
	}

	return report, nil
}

func previewBootstrapHandle(ctx context.Context) (*store.Handle, string, error) {
	handle, err := openVaultHandleFn(ctx)
	if err == nil {
		return handle, "existing", nil
	}
	if errors.Is(err, store.ErrVaultNotInitialized) {
		return nil, "would_create", nil
	}
	return nil, "", err
}

func summarizeProof(proof map[string]profiles.SupportCheck) profiles.SupportCheck {
	status := "pass"
	failures := 0
	warnings := 0
	for _, check := range proof {
		switch check.Status {
		case "fail":
			failures++
			status = "fail"
		case "warn":
			if status != "fail" {
				status = "warn"
			}
			warnings++
		}
	}
	detail := fmt.Sprintf("support proof dimensions: %d failing, %d warning", failures, warnings)
	recovery := ""
	if failures > 0 {
		recovery = "fix the failing support-proof dimensions before treating this profile as first-class shipped support"
	}
	return profiles.SupportCheck{Status: status, Detail: detail, Recovery: recovery}
}

func genericCompatibilitySurface() map[string]any {
	return map[string]any{
		"id":                  "generic",
		"name":                "Generic Broker Path",
		"support_tier":        profiles.SupportTierGenericCompatible,
		"compatibility_label": profiles.CompatibilityLabelGeneric,
		"first_class":         false,
		"transport":           "mcp-stdio",
		"command":             []string{"hasp", "mcp"},
		"setup_command":       "hasp bootstrap generic --project-root <repo>",
		"first_proof_command": setupBrokeredProofCommand("<repo>", "@SECRET_NAME"),
		"doctor_command":      "hasp bootstrap doctor generic --project-root <repo>",
		"notes": []string{
			"generic compatibility is intentionally separate from first-class support",
			"use the generic path when the agent can speak stdio MCP or call the broker CLI directly",
			"treat the generic path as a first brokered proof path, not as first-class support",
		},
	}
}

func convenienceModeSurface() map[string]any {
	return map[string]any{
		"id":                  "convenience-mode",
		"name":                "Explicit Convenience Mode",
		"support_tier":        profiles.SupportTierConvenienceMode,
		"compatibility_label": profiles.CompatibilityLabelConvenience,
		"first_class":         false,
		"command":             []string{"hasp", "write-env"},
		"notes": []string{
			"convenience mode is explicit and separate from both first-class support and generic compatibility",
			"bootstrap never auto-creates repo-visible env files or auto-falls back into write-env",
		},
	}
}

func bootstrapHookPresent(projectRoot string) bool {
	if strings.TrimSpace(projectRoot) == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(projectRoot, ".git", "hooks", "pre-commit"))
	return err == nil
}

func bootstrapAliasContext(ctx context.Context, projectRoot string) (map[string]string, store.Binding, []store.VisibleReference, error) {
	handle, _, err := previewBootstrapHandle(ctx)
	if err != nil {
		return nil, store.Binding{}, nil, err
	}
	if handle == nil {
		return map[string]string{}, store.Binding{}, nil, nil
	}
	binding, visible, err := resolveBindingViewBootstrapFn(handle, ctx, projectRoot)
	if err != nil {
		return nil, store.Binding{}, nil, err
	}
	return cloneAliasSet(binding.Aliases), binding, visible, nil
}
