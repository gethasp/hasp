package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

var persistEnvelope = (*Handle).persist

func (h *Handle) UpsertItem(name string, kind ItemKind, value []byte, metadata ItemMetadata) (Item, error) {
	if name = strings.TrimSpace(name); name == "" {
		return Item{}, errors.New("item name is required")
	}
	if kind != ItemKindKV && kind != ItemKindFile {
		return Item{}, fmt.Errorf("unsupported item kind %q", kind)
	}
	if h.state.Items == nil {
		h.state.Items = map[string]Item{}
	}
	for id, existing := range h.state.Items {
		if existing.Name == name {
			existing.Kind = kind
			existing.Value = slices.Clone(value)
			existing.Metadata = metadata
			existing.UpdatedAt = h.store.now()
			existing.DeletedAt = nil
			h.state.Items[id] = existing
			err := persistEnvelope(h)
			if err == nil {
				h.store.appendAuditBestEffort("item.upsert", "user", map[string]any{"name": existing.Name, "kind": existing.Kind})
			}
			return existing, err
		}
	}
	item := Item{
		ID:        randomHex(16),
		Name:      name,
		Kind:      kind,
		Value:     slices.Clone(value),
		Metadata:  metadata,
		CreatedAt: h.store.now(),
		UpdatedAt: h.store.now(),
	}
	h.state.Items[item.ID] = item
	err := persistEnvelope(h)
	if err == nil {
		h.store.appendAuditBestEffort("item.upsert", "user", map[string]any{"name": item.Name, "kind": item.Kind})
	}
	return item, err
}

func (h *Handle) GetItem(name string) (Item, error) {
	for _, item := range h.state.Items {
		if item.Name == name && item.DeletedAt == nil {
			item.Value = slices.Clone(item.Value)
			return item, nil
		}
	}
	return Item{}, ErrItemNotFound
}

func (h *Handle) DeleteItem(name string) error {
	for id, item := range h.state.Items {
		if item.Name == name && item.DeletedAt == nil {
			now := h.store.now()
			item.DeletedAt = &now
			item.UpdatedAt = now
			h.state.Items[id] = item
			h.removeItemFromBindings(item.Name)
			err := persistEnvelope(h)
			if err == nil {
				h.store.appendAuditBestEffort("item.delete", "user", map[string]any{"name": item.Name})
			}
			return err
		}
	}
	return ErrItemNotFound
}

func (h *Handle) removeItemFromBindings(itemName string) int {
	removed := 0
	for root, binding := range h.state.Bindings {
		if len(binding.Aliases) == 0 {
			continue
		}
		changed := false
		for alias, existing := range binding.Aliases {
			if existing != itemName {
				continue
			}
			delete(binding.Aliases, alias)
			removed++
			changed = true
		}
		if changed {
			h.state.Bindings[root] = binding
		}
	}
	return removed
}

func (h *Handle) ListItems() []Item {
	items := make([]Item, 0, len(h.state.Items))
	for _, item := range h.state.Items {
		if item.DeletedAt != nil {
			continue
		}
		item.Value = slices.Clone(item.Value)
		items = append(items, item)
	}
	slices.SortFunc(items, func(a, b Item) int {
		return strings.Compare(a.Name, b.Name)
	})
	return items
}

func (h *Handle) persist() error {
	envelope, err := h.store.readEnvelope()
	if err != nil {
		return err
	}
	envelope.Header.UpdatedAt = h.store.now()
	data, err := sealState(h.vaultKey, h.state)
	if err != nil {
		return err
	}
	envelope.Data = data
	return h.store.writeEnvelopeFile(envelope)
}
