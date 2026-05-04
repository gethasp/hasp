package store

import "context"

type CaptureResult struct {
	Reference string   `json:"reference"`
	Alias     string   `json:"alias,omitempty"`
	ItemName  string   `json:"item_name"`
	ItemKind  ItemKind `json:"item_kind"`
}

func (h *Handle) Capture(ctx context.Context, projectRoot string, name string, kind ItemKind, value []byte, bindToProject bool) (CaptureResult, error) {
	item, err := h.UpsertItem(name, kind, value, ItemMetadata{})
	if err != nil {
		return CaptureResult{}, err
	}
	result := CaptureResult{
		Reference: item.Name,
		ItemName:  item.Name,
		ItemKind:  item.Kind,
	}
	if bindToProject {
		alias, err := h.BindItemAlias(ctx, projectRoot, item.Name)
		if err != nil {
			return CaptureResult{}, err
		}
		result.Reference = alias
		result.Alias = alias
	}
	h.store.appendAuditBestEffort("capture", "system", map[string]any{"item_name": item.Name, "reference": result.Reference})
	return result, nil
}
