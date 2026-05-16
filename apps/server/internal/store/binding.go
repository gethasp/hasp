package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/gitsafe"
)

var filepathAbsFn = filepath.Abs

const manifestFilename = ".hasp.manifest.json"

type Binding struct {
	ID                   string            `json:"id"`
	CanonicalRoot        string            `json:"canonical_root"`
	Aliases              map[string]string `json:"aliases"`
	DefaultCapturePolicy SecretPolicy      `json:"default_capture_policy"`
	HookInstalled        bool              `json:"hook_installed"`
}

type RepoManifest struct {
	Version              string                `json:"version"`
	Project              ManifestProject       `json:"project,omitempty"`
	References           []ManifestReference   `json:"references"`
	Requirements         []ManifestRequirement `json:"requirements,omitempty"`
	Targets              []ManifestTarget      `json:"targets,omitempty"`
	DefaultCapturePolicy SecretPolicy          `json:"default_capture_policy,omitempty"`
}

type ManifestProject struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type ManifestReference struct {
	Alias string `json:"alias"`
	Item  string `json:"item"`
}

type ManifestRequirement struct {
	Ref            string   `json:"ref"`
	Kind           ItemKind `json:"kind"`
	Required       bool     `json:"required"`
	Classification string   `json:"classification"`
	Description    string   `json:"description,omitempty"`
}

type ManifestTarget struct {
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Root        string             `json:"root,omitempty"`
	Command     []string           `json:"command,omitempty"`
	Delivery    []ManifestDelivery `json:"delivery,omitempty"`
	Examples    []ManifestExample  `json:"examples,omitempty"`
}

type ManifestDelivery struct {
	As     string `json:"as"`
	Name   string `json:"name"`
	Ref    string `json:"ref"`
	Output string `json:"output,omitempty"`
}

type ManifestExample struct {
	Format string `json:"format"`
	Path   string `json:"path"`
}

type VisibleReference struct {
	Alias          string       `json:"alias"`
	ItemName       string       `json:"item_name"`
	NamedReference string       `json:"named_reference,omitempty"`
	Kind           ItemKind     `json:"kind"`
	PolicyLevel    SecretPolicy `json:"policy_level"`
	LeaseStatus    string       `json:"lease_status"`
}

var ErrBindingConflict = errors.New("binding alias conflict")

func (h *Handle) UpsertBinding(ctx context.Context, projectPath string, aliases map[string]string, defaultPolicy SecretPolicy, hookInstalled bool) (Binding, error) {
	root, err := CanonicalProjectPath(projectPath)
	if err != nil {
		return Binding{}, err
	}
	if h.state.Bindings == nil {
		h.state.Bindings = map[string]Binding{}
	}
	binding, ok := h.state.Bindings[root]
	if !ok {
		id, idErr := randomHex(12)
		if idErr != nil {
			return Binding{}, fmt.Errorf("mint binding id: %w", idErr)
		}
		binding = Binding{
			ID:            id,
			CanonicalRoot: root,
			Aliases:       map[string]string{},
		}
	}
	for alias, itemName := range aliases {
		binding.Aliases[strings.TrimSpace(alias)] = strings.TrimSpace(itemName)
	}
	binding.DefaultCapturePolicy = normalizePolicy(defaultPolicy)
	binding.HookInstalled = binding.HookInstalled || hookInstalled
	h.state.Bindings[root] = binding
	err = h.persist()
	if err == nil {
		h.store.appendAuditBestEffort("binding.upsert", "user", map[string]any{"root": root})
	}
	return binding, err
}

func (h *Handle) BindItemAlias(ctx context.Context, projectPath string, itemName string) (string, error) {
	root, err := h.bindingRoot(ctx, projectPath)
	if err != nil {
		return "", err
	}
	item, err := h.GetItem(itemName)
	if err != nil {
		return "", err
	}
	binding, ok := h.state.Bindings[root]
	if !ok {
		id, idErr := randomHex(12)
		if idErr != nil {
			return "", fmt.Errorf("mint binding id: %w", idErr)
		}
		binding = Binding{
			ID:                   id,
			CanonicalRoot:        root,
			Aliases:              map[string]string{},
			DefaultCapturePolicy: normalizePolicy(item.Metadata.Policy),
		}
	}
	if binding.Aliases == nil {
		binding.Aliases = map[string]string{}
	}
	for alias, existing := range binding.Aliases {
		if existing == item.Name {
			return alias, nil
		}
	}
	alias := GenerateNeutralAlias(item.Kind, binding.Aliases)
	binding.Aliases[alias] = item.Name
	h.state.Bindings[root] = binding
	err = h.persist()
	if err == nil {
		h.store.appendAuditBestEffort("binding.alias_bind", "user", map[string]any{"root": root, "alias": alias, "item": item.Name})
	}
	return alias, err
}

func (h *Handle) ResolveBindingView(ctx context.Context, projectPath string) (Binding, []VisibleReference, error) {
	resolved, err := h.resolvedBinding(ctx, projectPath)
	if err != nil {
		return Binding{}, nil, err
	}

	visible := make([]VisibleReference, 0, len(resolved.Aliases))
	for alias, itemName := range resolved.Aliases {
		item, err := h.GetItem(itemName)
		if err != nil {
			return Binding{}, nil, err
		}
		visible = append(visible, VisibleReference{
			Alias:          alias,
			ItemName:       item.Name,
			NamedReference: NamedReference(item.Name),
			Kind:           item.Kind,
			PolicyLevel:    normalizePolicy(item.Metadata.Policy),
			LeaseStatus:    "inactive",
		})
	}
	sortVisibleReferences(visible)
	return resolved, visible, nil
}

func (h *Handle) resolvedBinding(ctx context.Context, projectPath string) (Binding, error) {
	root, err := h.bindingRoot(ctx, projectPath)
	if err != nil {
		return Binding{}, err
	}
	local := h.state.Bindings[root]
	manifest, err := LoadRepoManifest(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Binding{}, err
	}

	resolved := Binding{
		ID:                   local.ID,
		CanonicalRoot:        root,
		Aliases:              map[string]string{},
		DefaultCapturePolicy: local.DefaultCapturePolicy,
		HookInstalled:        local.HookInstalled,
	}
	if resolved.DefaultCapturePolicy == "" && manifest.DefaultCapturePolicy != "" {
		resolved.DefaultCapturePolicy = manifest.DefaultCapturePolicy
	}

	for _, ref := range manifest.References {
		if strings.TrimSpace(ref.Alias) == "" || strings.TrimSpace(ref.Item) == "" {
			continue
		}
		resolved.Aliases[ref.Alias] = ref.Item
	}
	for alias, item := range local.Aliases {
		if existing, ok := resolved.Aliases[alias]; ok && existing != item {
			return Binding{}, fmt.Errorf("%w: alias %q maps to %q and %q", ErrBindingConflict, alias, existing, item)
		}
		resolved.Aliases[alias] = item
	}
	return resolved, nil
}

func (h *Handle) DeleteBinding(ctx context.Context, projectPath string) error {
	root, err := h.bindingRoot(ctx, projectPath)
	if err != nil {
		return err
	}
	delete(h.state.Bindings, root)
	err = h.persist()
	if err == nil {
		h.store.appendAuditBestEffort("binding.delete", "user", map[string]any{"root": root})
	}
	return err
}

func (h *Handle) bindingRoot(ctx context.Context, projectPath string) (string, error) {
	exact, exactErr := CanonicalProjectPath(projectPath)
	if exactErr != nil {
		return "", exactErr
	}
	if _, ok := h.state.Bindings[exact]; ok {
		return exact, nil
	}
	root, err := CanonicalProjectRoot(ctx, projectPath)
	if err != nil {
		return exact, nil
	}
	return root, nil
}

func CanonicalProjectRoot(ctx context.Context, projectPath string) (string, error) {
	if projectPath == "" {
		projectPath = "."
	}
	abs, err := filepathAbsFn(projectPath)
	if err != nil {
		return "", fmt.Errorf("resolve project path: %w", err)
	}
	if root, err := gitsafe.TopLevelCached(ctx, abs); err == nil {
		return normalizeRoot(root), nil
	}
	return normalizeRoot(abs), nil
}

func CanonicalProjectPath(projectPath string) (string, error) {
	if projectPath == "" {
		projectPath = "."
	}
	abs, err := filepathAbsFn(projectPath)
	if err != nil {
		return "", fmt.Errorf("resolve project path: %w", err)
	}
	return normalizeRoot(abs), nil
}

func LoadRepoManifest(root string) (RepoManifest, error) {
	manifest, _, err := LoadRepoManifestWithIdentity(root)
	return manifest, err
}

func GenerateNeutralAlias(kind ItemKind, existing map[string]string) string {
	prefix := "credential"
	switch kind {
	case ItemKindKV:
		prefix = "secret"
	case ItemKindFile:
		prefix = "file"
	}
	for i := 1; ; i++ {
		alias := fmt.Sprintf("%s_%02d", prefix, i)
		if _, ok := existing[alias]; !ok {
			return alias
		}
	}
}

func normalizePolicy(policy SecretPolicy) SecretPolicy {
	switch policy {
	case PolicySession, PolicyAccess:
		return policy
	default:
		return PolicyAuto
	}
}

func sortVisibleReferences(values []VisibleReference) {
	slices.SortFunc(values, func(a, b VisibleReference) int {
		return strings.Compare(a.Alias, b.Alias)
	})
}

func normalizeRoot(path string) string {
	cleaned := filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return cleaned
	}
	return resolved
}
