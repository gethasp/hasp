package store

import (
	"fmt"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

func (h *Handle) GrantProjectLease(bindingID string, sessionToken string, scope GrantScope, ttl time.Duration) (ProjectLease, error) {
	expiresAt, err := computeExpiry(h.store.now(), scope, ttl)
	if err != nil {
		return ProjectLease{}, err
	}
	lease := ProjectLease{
		ID:           randomHex(10),
		BindingID:    bindingID,
		SessionToken: sessionToken,
		Scope:        scope,
		ExpiresAt:    expiresAt,
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
	grant := SecretGrant{
		ID:              randomHex(10),
		BindingID:       bindingID,
		ItemName:        itemName,
		SessionToken:    sessionToken,
		Scope:           scope,
		RelaxedByWindow: relaxed,
		ExpiresAt:       expiresAt,
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
	grant := ConvenienceGrant{
		ID:                  randomHex(10),
		ProjectBindingID:    bindingID,
		LeaseID:             lease.ID,
		DestinationPathHash: hashString(destinationPath),
		ResolvedSetHash:     hashResolvedSet(resolvedSet),
		GrantedBy:           grantedBy,
		Scope:               scope,
		ExpiresAt:           expiresAt,
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
	err := h.persist()
	if err == nil {
		h.store.appendAuditBestEffort(audit.EventDeny, "user", map[string]any{"action": "grant.project.revoke", "binding_id": bindingID})
	}
	return err
}
