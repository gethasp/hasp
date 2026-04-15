package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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
	Version              string              `json:"version"`
	References           []ManifestReference `json:"references"`
	DefaultCapturePolicy SecretPolicy        `json:"default_capture_policy,omitempty"`
}

type ManifestReference struct {
	Alias string `json:"alias"`
	Item  string `json:"item"`
}

type VisibleReference struct {
	Alias       string       `json:"alias"`
	Kind        ItemKind     `json:"kind"`
	PolicyLevel SecretPolicy `json:"policy_level"`
	LeaseStatus string       `json:"lease_status"`
}

var ErrBindingConflict = errors.New("binding alias conflict")

func (h *Handle) UpsertBinding(ctx context.Context, projectPath string, aliases map[string]string, defaultPolicy SecretPolicy, hookInstalled bool) (Binding, error) {
	root, err := CanonicalProjectRoot(ctx, projectPath)
	if err != nil {
		return Binding{}, err
	}
	if h.state.Bindings == nil {
		h.state.Bindings = map[string]Binding{}
	}
	binding, ok := h.state.Bindings[root]
	if !ok {
		binding = Binding{
			ID:            randomHex(12),
			CanonicalRoot: root,
			Aliases:       map[string]string{},
		}
	}
	for alias, itemName := range aliases {
		binding.Aliases[strings.TrimSpace(alias)] = strings.TrimSpace(itemName)
	}
	binding.DefaultCapturePolicy = normalizePolicy(defaultPolicy)
	binding.HookInstalled = hookInstalled
	h.state.Bindings[root] = binding
	err = h.persist()
	if err == nil {
		h.store.appendAuditBestEffort("binding.upsert", "user", map[string]any{"root": root})
	}
	return binding, err
}

func (h *Handle) BindItemAlias(ctx context.Context, projectPath string, itemName string) (string, error) {
	root, err := CanonicalProjectRoot(ctx, projectPath)
	if err != nil {
		return "", err
	}
	item, err := h.GetItem(itemName)
	if err != nil {
		return "", err
	}
	binding, ok := h.state.Bindings[root]
	if !ok {
		binding = Binding{
			ID:                   randomHex(12),
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
			Alias:       alias,
			Kind:        item.Kind,
			PolicyLevel: normalizePolicy(item.Metadata.Policy),
			LeaseStatus: "inactive",
		})
	}
	sortVisibleReferences(visible)
	return resolved, visible, nil
}

func (h *Handle) resolvedBinding(ctx context.Context, projectPath string) (Binding, error) {
	root, err := CanonicalProjectRoot(ctx, projectPath)
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
	root, err := CanonicalProjectRoot(ctx, projectPath)
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

func CanonicalProjectRoot(ctx context.Context, projectPath string) (string, error) {
	if projectPath == "" {
		projectPath = "."
	}
	abs, err := filepathAbsFn(projectPath)
	if err != nil {
		return "", fmt.Errorf("resolve project path: %w", err)
	}
	cmd := exec.CommandContext(ctx, "git", "-C", abs, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err == nil {
		return normalizeRoot(strings.TrimSpace(string(out))), nil
	}
	return normalizeRoot(abs), nil
}

func LoadRepoManifest(root string) (RepoManifest, error) {
	path := filepath.Join(root, manifestFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		return RepoManifest{}, err
	}
	var manifest RepoManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return RepoManifest{}, fmt.Errorf("decode repo manifest: %w", err)
	}
	return manifest, nil
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
