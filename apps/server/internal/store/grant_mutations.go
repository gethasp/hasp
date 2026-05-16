package store

import (
	"fmt"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

func (h *Handle) GrantProjectLease(bindingID string, sessionToken string, scope GrantScope, ttl time.Duration) (ProjectLease, error) {
	expiresAt, err := computeExpiry(h.store.now(), scope, ttl)
	if err != nil {
		return ProjectLease{}, err
	}
	id, err := randomHex(10)
	if err != nil {
		return ProjectLease{}, fmt.Errorf("mint project lease id: %w", err)
	}
	lease := ProjectLease{
		ID:           id,
		BindingID:    bindingID,
		SessionToken: sessionToken,
		Scope:        scope,
		ExpiresAt:    expiresAt,
	}
	if scope == GrantOnce {
		unlock := lockVaultStatePath(h.store.paths.StatePath)
		defer unlock()
		if err := h.refreshStateUnlocked(); err != nil {
			return ProjectLease{}, err
		}
		key := leaseKey(bindingID, sessionToken)
		if existing, ok := h.state.ProjectLeases[key]; ok {
			if existing.Scope == GrantOnce || grantIsActive(existing.Scope, existing.ExpiresAt, existing.RevokedAt, existing.UsedAt, h.store.now()) {
				return existing, nil
			}
		}
		h.state.ProjectLeases[key] = lease
		err = h.persistUnlocked()
		if err == nil {
			h.store.appendAuditBestEffort("grant.project", "user", map[string]any{"binding_id": bindingID, "scope": scope})
		}
		return lease, err
	}
	h.state.ProjectLeases[leaseKey(bindingID, sessionToken)] = lease
	err = h.persist()
	if err == nil {
		h.store.appendAuditBestEffort("grant.project", "user", map[string]any{"binding_id": bindingID, "scope": scope})
	}
	return lease, err
}

func (h *Handle) ConsumeProjectLease(bindingID string, sessionToken string) error {
	key := leaseKey(bindingID, sessionToken)
	lease, ok := h.state.ProjectLeases[key]
	if !ok {
		return nil
	}
	if lease.Scope != GrantOnce {
		return nil
	}
	now := h.store.now()
	lease.UsedAt = &now
	h.state.ProjectLeases[key] = lease
	err := h.persist()
	if err == nil {
		h.store.appendAuditBestEffort("grant.project.consume", "user", map[string]any{"binding_id": bindingID})
	}
	return err
}

func (h *Handle) GrantSecretUse(bindingID string, sessionToken string, itemName string, scope GrantScope, ttl time.Duration, relaxed bool) (SecretGrant, error) {
	expiresAt, err := computeExpiry(h.store.now(), scope, ttl)
	if err != nil {
		return SecretGrant{}, err
	}
	id, err := randomHex(10)
	if err != nil {
		return SecretGrant{}, fmt.Errorf("mint secret grant id: %w", err)
	}
	grant := SecretGrant{
		ID:              id,
		BindingID:       bindingID,
		ItemName:        itemName,
		SessionToken:    sessionToken,
		Scope:           scope,
		RelaxedByWindow: relaxed,
		ExpiresAt:       expiresAt,
	}
	if scope == GrantOnce {
		unlock := lockVaultStatePath(h.store.paths.StatePath)
		defer unlock()
		if err := h.refreshStateUnlocked(); err != nil {
			return SecretGrant{}, err
		}
		key := secretGrantKey(bindingID, sessionToken, itemName)
		if existing, ok := h.state.SecretGrants[key]; ok {
			if existing.Scope == GrantOnce || grantIsActive(existing.Scope, existing.ExpiresAt, existing.RevokedAt, existing.UsedAt, h.store.now()) {
				return existing, nil
			}
		}
		h.state.SecretGrants[key] = grant
		err = h.persistUnlocked()
		if err == nil {
			h.store.appendAuditBestEffort("grant.secret", "user", map[string]any{"binding_id": bindingID, "item": itemName, "scope": scope, "relaxed": relaxed})
		}
		return grant, err
	}
	h.state.SecretGrants[secretGrantKey(bindingID, sessionToken, itemName)] = grant
	err = h.persist()
	if err == nil {
		h.store.appendAuditBestEffort("grant.secret", "user", map[string]any{"binding_id": bindingID, "item": itemName, "scope": scope, "relaxed": relaxed})
	}
	return grant, err
}

func (h *Handle) ConsumeSecretGrant(bindingID string, sessionToken string, itemName string) error {
	key := secretGrantKey(bindingID, sessionToken, itemName)
	grant, ok := h.state.SecretGrants[key]
	if !ok {
		return nil
	}
	if grant.Scope != GrantOnce {
		return nil
	}
	now := h.store.now()
	grant.UsedAt = &now
	h.state.SecretGrants[key] = grant
	err := h.persist()
	if err == nil {
		h.store.appendAuditBestEffort("grant.secret.consume", "user", map[string]any{"binding_id": bindingID, "item": itemName})
	}
	return err
}

func (h *Handle) GrantConvenience(bindingID string, sessionToken string, destinationPath string, resolvedSet []string, grantedBy string, scope GrantScope, ttl time.Duration) (ConvenienceGrant, error) {
	expiresAt, err := computeExpiry(h.store.now(), scope, ttl)
	if err != nil {
		return ConvenienceGrant{}, err
	}
	lease, ok := h.state.ProjectLeases[leaseKey(bindingID, sessionToken)]
	if !ok || !grantIsActive(lease.Scope, lease.ExpiresAt, lease.RevokedAt, lease.UsedAt, h.store.now()) {
		return ConvenienceGrant{}, fmt.Errorf("active project lease required for convenience grant")
	}
	id, err := randomHex(10)
	if err != nil {
		return ConvenienceGrant{}, fmt.Errorf("mint convenience grant id: %w", err)
	}
	grant := ConvenienceGrant{
		ID:                  id,
		ProjectBindingID:    bindingID,
		LeaseID:             lease.ID,
		DestinationPathHash: hashString(destinationPath),
		ResolvedSetHash:     hashResolvedSet(resolvedSet),
		GrantedBy:           grantedBy,
		Scope:               scope,
		ExpiresAt:           expiresAt,
	}
	if scope == GrantOnce {
		leaseKeyValue := leaseKey(bindingID, sessionToken)
		priorLease, hadPriorLease := h.state.ProjectLeases[leaseKeyValue]
		unlock := lockVaultStatePath(h.store.paths.StatePath)
		defer unlock()
		if err := h.refreshStateUnlocked(); err != nil {
			return ConvenienceGrant{}, err
		}
		lease, ok = h.state.ProjectLeases[leaseKeyValue]
		if !ok && hadPriorLease && grantIsActive(priorLease.Scope, priorLease.ExpiresAt, priorLease.RevokedAt, priorLease.UsedAt, h.store.now()) {
			lease = priorLease
			h.state.ProjectLeases[leaseKeyValue] = priorLease
			ok = true
		}
		if !ok || !grantIsActive(lease.Scope, lease.ExpiresAt, lease.RevokedAt, lease.UsedAt, h.store.now()) {
			return ConvenienceGrant{}, fmt.Errorf("active project lease required for convenience grant")
		}
		key := convenienceGrantKey(bindingID, destinationPath, resolvedSet)
		if existing, ok := h.state.ConvenienceGrants[key]; ok {
			if existing.Scope == GrantOnce || grantIsActive(existing.Scope, existing.ExpiresAt, existing.RevokedAt, existing.UsedAt, h.store.now()) {
				return existing, nil
			}
		}
		h.state.ConvenienceGrants[key] = grant
		err = h.persistUnlocked()
		if err == nil {
			h.store.appendAuditBestEffort(audit.EventWriteEnv, "user", map[string]any{"action": "grant", "binding_id": bindingID, "destination_path": destinationPath, "scope": scope})
		}
		return grant, err
	}
	h.state.ConvenienceGrants[convenienceGrantKey(bindingID, destinationPath, resolvedSet)] = grant
	err = h.persist()
	if err == nil {
		h.store.appendAuditBestEffort(audit.EventWriteEnv, "user", map[string]any{"action": "grant", "binding_id": bindingID, "destination_path": destinationPath, "scope": scope})
	}
	return grant, err
}

func (h *Handle) ConsumeConvenienceGrant(bindingID string, destinationPath string, resolvedSet []string) error {
	key := convenienceGrantKey(bindingID, destinationPath, resolvedSet)
	grant, ok := h.state.ConvenienceGrants[key]
	if !ok {
		return nil
	}
	if grant.Scope != GrantOnce {
		return nil
	}
	now := h.store.now()
	grant.UsedAt = &now
	h.state.ConvenienceGrants[key] = grant
	err := h.persist()
	if err == nil {
		h.store.appendAuditBestEffort(audit.EventWriteEnv, "user", map[string]any{"action": "consume", "binding_id": bindingID, "destination_path": destinationPath})
	}
	return err
}

func (h *Handle) GrantPlaintextUse(sessionToken string, itemName string, action PlaintextAction, grantedBy string, scope GrantScope, ttl time.Duration) (PlaintextGrant, error) {
	if sessionToken == "" {
		return PlaintextGrant{}, fmt.Errorf("session token is required")
	}
	itemName = strings.TrimSpace(itemName)
	if itemName == "" {
		return PlaintextGrant{}, fmt.Errorf("item name is required")
	}
	if action != PlaintextReveal && action != PlaintextCopy {
		return PlaintextGrant{}, fmt.Errorf("unsupported plaintext action %q", action)
	}
	if scope != GrantOnce {
		return PlaintextGrant{}, fmt.Errorf("plaintext grants must use scope %q", GrantOnce)
	}
	if ttl <= 0 {
		ttl = DefaultPlaintextGrantTTL
	}
	if ttl > MaxPlaintextGrantTTL {
		return PlaintextGrant{}, fmt.Errorf("plaintext grants may not exceed %s", MaxPlaintextGrantTTL)
	}
	expiresAt := h.store.now().Add(ttl)
	id, err := randomHex(10)
	if err != nil {
		return PlaintextGrant{}, fmt.Errorf("mint plaintext grant id: %w", err)
	}
	grant := PlaintextGrant{
		ID:           id,
		SessionToken: sessionToken,
		ItemName:     itemName,
		Action:       action,
		GrantedBy:    grantedBy,
		Scope:        GrantOnce,
		ExpiresAt:    &expiresAt,
	}
	h.state.PlaintextGrants[plaintextGrantKey(sessionToken, itemName, action)] = grant
	err = h.persist()
	if err == nil {
		h.store.appendAuditBestEffort(audit.EventOverride, "user", map[string]any{
			"action":           "grant.plaintext",
			"item":             itemName,
			"plaintext_action": action,
			"scope":            grant.Scope,
			"ttl_seconds":      int(ttl.Seconds()),
		})
	}
	return grant, err
}

func (h *Handle) ConsumePlaintextGrant(sessionToken string, itemName string, action PlaintextAction) error {
	key := plaintextGrantKey(sessionToken, itemName, action)
	grant, ok := h.state.PlaintextGrants[key]
	if !ok {
		return nil
	}
	if grant.Scope != GrantOnce {
		return nil
	}
	now := h.store.now()
	grant.UsedAt = &now
	h.state.PlaintextGrants[key] = grant
	err := h.persist()
	if err == nil {
		h.store.appendAuditBestEffort(audit.EventOverride, "user", map[string]any{"action": "consume.plaintext", "item": itemName, "plaintext_action": action})
	}
	return err
}

func (h *Handle) PlaintextGrantActive(sessionToken string, itemName string, action PlaintextAction) bool {
	grant, ok := h.state.PlaintextGrants[plaintextGrantKey(sessionToken, itemName, action)]
	return ok && grantIsActive(grant.Scope, grant.ExpiresAt, grant.RevokedAt, grant.UsedAt, h.store.now())
}

func normalizeSecretMutationGrant(bindingID string, sessionToken string, itemName string, action SecretMutationAction, scope GrantScope, ttl time.Duration) (string, time.Duration, error) {
	if strings.TrimSpace(bindingID) == "" {
		return "", 0, fmt.Errorf("binding id is required")
	}
	if strings.TrimSpace(sessionToken) == "" {
		return "", 0, fmt.Errorf("session token is required")
	}
	itemName = strings.TrimSpace(itemName)
	if itemName == "" {
		return "", 0, fmt.Errorf("item name is required")
	}
	if action != SecretMutationDelete && action != SecretMutationExpose && action != SecretMutationHide {
		return "", 0, fmt.Errorf("unsupported secret mutation action %q", action)
	}
	if scope != GrantOnce {
		return "", 0, fmt.Errorf("secret mutation grants must use scope %q", GrantOnce)
	}
	if ttl <= 0 {
		ttl = DefaultMutationGrantTTL
	}
	if ttl > MaxMutationGrantTTL {
		return "", 0, fmt.Errorf("secret mutation grants may not exceed %s", MaxMutationGrantTTL)
	}
	return itemName, ttl, nil
}

func (h *Handle) newSecretMutationGrant(bindingID string, sessionToken string, itemName string, action SecretMutationAction, grantedBy string, ttl time.Duration) (MutationGrant, error) {
	expiresAt := h.store.now().Add(ttl)
	id, err := randomHex(10)
	if err != nil {
		return MutationGrant{}, fmt.Errorf("mint mutation grant id: %w", err)
	}
	grant := MutationGrant{
		ID:           id,
		BindingID:    bindingID,
		ItemName:     itemName,
		SessionToken: sessionToken,
		Action:       action,
		GrantedBy:    grantedBy,
		Scope:        GrantOnce,
		ExpiresAt:    &expiresAt,
	}
	return grant, nil
}

func (h *Handle) appendSecretMutationGrantAudit(bindingID string, itemName string, action SecretMutationAction, ttl time.Duration) {
	h.store.appendAuditBestEffort(audit.EventOverride, "user", map[string]any{
		"action":          "grant.secret_mutation",
		"binding_id":      bindingID,
		"item":            itemName,
		"mutation_action": action,
		"ttl_seconds":     int(ttl.Seconds()),
	})
}

func (h *Handle) GrantSecretMutation(bindingID string, sessionToken string, itemName string, action SecretMutationAction, grantedBy string, scope GrantScope, ttl time.Duration) (MutationGrant, error) {
	itemName, ttl, err := normalizeSecretMutationGrant(bindingID, sessionToken, itemName, action, scope, ttl)
	if err != nil {
		return MutationGrant{}, err
	}
	if !h.projectLeaseActive(bindingID, sessionToken) {
		return MutationGrant{}, fmt.Errorf("active project lease required for secret mutation grant")
	}
	grant, err := h.newSecretMutationGrant(bindingID, sessionToken, itemName, action, grantedBy, ttl)
	if err != nil {
		return MutationGrant{}, err
	}
	key := mutationGrantKey(bindingID, sessionToken, itemName, action)
	previous, hadPrevious := h.state.MutationGrants[key]
	h.state.MutationGrants[key] = grant
	if err := h.persist(); err != nil {
		if hadPrevious {
			h.state.MutationGrants[key] = previous
		} else {
			delete(h.state.MutationGrants, key)
		}
		return MutationGrant{}, err
	}
	h.appendSecretMutationGrantAudit(bindingID, itemName, action, ttl)
	return grant, nil
}

func (h *Handle) ConsumeSecretMutationGrant(bindingID string, sessionToken string, itemName string, action SecretMutationAction) error {
	itemName = strings.TrimSpace(itemName)
	key := mutationGrantKey(bindingID, sessionToken, itemName, action)
	grant, ok := h.state.MutationGrants[key]
	if !ok || !h.mutationGrantActive(bindingID, sessionToken, itemName, action) {
		return fmt.Errorf("secret mutation grant required for %s", action)
	}
	now := h.store.now()
	grant.UsedAt = &now
	h.state.MutationGrants[key] = grant
	err := h.persist()
	if err == nil {
		h.store.appendAuditBestEffort(audit.EventOverride, "user", map[string]any{
			"action":          "consume.secret_mutation",
			"binding_id":      bindingID,
			"item":            itemName,
			"mutation_action": action,
		})
	}
	return err
}

func (h *Handle) RevokeProjectLease(bindingID string, sessionToken string) error {
	key := leaseKey(bindingID, sessionToken)
	lease, ok := h.state.ProjectLeases[key]
	if !ok {
		return nil
	}
	now := h.store.now()
	lease.RevokedAt = &now
	h.state.ProjectLeases[key] = lease
	for key, grant := range h.state.ConvenienceGrants {
		if grant.ProjectBindingID == bindingID && grant.LeaseID == lease.ID && grant.RevokedAt == nil {
			grant.RevokedAt = &now
			h.state.ConvenienceGrants[key] = grant
		}
	}
	for key, grant := range h.state.MutationGrants {
		if grant.BindingID == bindingID && grant.SessionToken == sessionToken && grant.RevokedAt == nil {
			grant.RevokedAt = &now
			h.state.MutationGrants[key] = grant
		}
	}
	err := h.persist()
	if err == nil {
		h.store.appendAuditBestEffort(audit.EventDeny, "user", map[string]any{"action": "grant.project.revoke", "binding_id": bindingID})
	}
	return err
}

func (h *Handle) RevokeGrantsForItem(itemName string) (int, error) {
	now := h.store.now()
	revoked := 0
	for key, grant := range h.state.SecretGrants {
		if grant.ItemName == itemName && grant.RevokedAt == nil {
			grant.RevokedAt = &now
			h.state.SecretGrants[key] = grant
			revoked++
		}
	}
	for key, grant := range h.state.PlaintextGrants {
		if grant.ItemName == itemName && grant.RevokedAt == nil {
			grant.RevokedAt = &now
			h.state.PlaintextGrants[key] = grant
			revoked++
		}
	}
	for key, grant := range h.state.MutationGrants {
		if grant.ItemName == itemName && grant.RevokedAt == nil {
			grant.RevokedAt = &now
			h.state.MutationGrants[key] = grant
			revoked++
		}
	}
	if revoked == 0 {
		return 0, nil
	}
	err := h.persist()
	if err == nil {
		h.store.appendAuditBestEffort(audit.EventDeny, "user", map[string]any{"action": "grant.item.revoke", "item": itemName, "revoked_count": revoked})
	}
	return revoked, err
}

func (h *Handle) RevokeAllGrants() (int, error) {
	now := h.store.now()
	revoked := 0
	for key, lease := range h.state.ProjectLeases {
		if lease.RevokedAt == nil {
			lease.RevokedAt = &now
			h.state.ProjectLeases[key] = lease
			revoked++
		}
	}
	for key, grant := range h.state.SecretGrants {
		if grant.RevokedAt == nil {
			grant.RevokedAt = &now
			h.state.SecretGrants[key] = grant
			revoked++
		}
	}
	for key, grant := range h.state.ConvenienceGrants {
		if grant.RevokedAt == nil {
			grant.RevokedAt = &now
			h.state.ConvenienceGrants[key] = grant
			revoked++
		}
	}
	for key, grant := range h.state.PlaintextGrants {
		if grant.RevokedAt == nil {
			grant.RevokedAt = &now
			h.state.PlaintextGrants[key] = grant
			revoked++
		}
	}
	for key, grant := range h.state.MutationGrants {
		if grant.RevokedAt == nil {
			grant.RevokedAt = &now
			h.state.MutationGrants[key] = grant
			revoked++
		}
	}
	if revoked == 0 {
		return 0, nil
	}
	err := h.persist()
	if err == nil {
		h.store.appendAuditBestEffort(audit.EventDeny, "user", map[string]any{"action": "grant.revoke_all", "revoked_count": revoked})
	}
	return revoked, err
}
