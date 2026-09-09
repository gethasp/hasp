package store

import "fmt"

type ItemClassification string

const (
	ClassificationConfidential  ItemClassification = "confidential"
	ClassificationConfiguration ItemClassification = "configuration"
)

// EffectiveClassification treats old records and unknown values as confidential.
func (item Item) EffectiveClassification() ItemClassification {
	if item.Classification == ClassificationConfiguration {
		return ClassificationConfiguration
	}
	return ClassificationConfidential
}

func (item Item) Confidential() bool {
	return item.EffectiveClassification() == ClassificationConfidential
}

// SetItemClassification is an operator mutation. Brokered secret writes cannot
// set this field through metadata. Every value upsert resets it to confidential.
func (h *Handle) SetItemClassification(name string, classification ItemClassification) (Item, error) {
	if classification != ClassificationConfidential && classification != ClassificationConfiguration {
		return Item{}, fmt.Errorf("unknown classification %q; expected confidential or configuration", classification)
	}
	unlock := lockVaultStatePath(h.store.paths.StatePath)
	defer unlock()
	if err := h.refreshStateUnlocked(); err != nil {
		return Item{}, err
	}
	item, err := h.GetItem(name)
	if err != nil {
		return Item{}, err
	}
	previous := item.EffectiveClassification()
	original := item
	item.Classification = classification
	item.UpdatedAt = h.store.now()
	h.state.Items[item.ID] = item
	if err := h.persistUnlocked(); err != nil {
		h.state.Items[item.ID] = original
		return Item{}, err
	}
	h.store.appendAuditBestEffort("item.classification", "user", map[string]any{"name": item.Name, "previous": previous, "classification": classification})
	item.Value = nil
	return item, nil
}
