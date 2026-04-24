package store

import (
	"context"
	"slices"
	"strings"
)

type ItemExposure struct {
	ProjectRoot string `json:"project_root"`
	Reference   string `json:"reference"`
}

func (h *Handle) ItemExposures(itemName string) []ItemExposure {
	exposures := make([]ItemExposure, 0)
	for root, binding := range h.state.Bindings {
		for alias, existing := range binding.Aliases {
			if existing != itemName {
				continue
			}
			exposures = append(exposures, ItemExposure{
				ProjectRoot: root,
				Reference:   alias,
			})
		}
	}
	slices.SortFunc(exposures, func(a, b ItemExposure) int {
		if cmp := strings.Compare(a.ProjectRoot, b.ProjectRoot); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Reference, b.Reference)
	})
	return exposures
}

func (h *Handle) HideItemFromProject(ctx context.Context, projectPath string, itemName string) ([]string, error) {
	root, err := CanonicalProjectRoot(ctx, projectPath)
	if err != nil {
		return nil, err
	}
	binding, ok := h.state.Bindings[root]
	if !ok || len(binding.Aliases) == 0 {
		return nil, nil
	}
	removed := make([]string, 0)
	for alias, existing := range binding.Aliases {
		if existing != itemName {
			continue
		}
		delete(binding.Aliases, alias)
		removed = append(removed, alias)
	}
	if len(removed) == 0 {
		return nil, nil
	}
	slices.Sort(removed)
	h.state.Bindings[root] = binding
	err = h.persist()
	if err == nil {
		h.store.appendAuditBestEffort("binding.alias_hide", "user", map[string]any{"root": root, "item": itemName, "references": removed})
	}
	return removed, err
}
