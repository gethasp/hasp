package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
)

func (h *Handle) Authorize(req AccessRequest) AccessDecision {
	return h.authorizeCurrent(req)
}

func (h *Handle) AuthorizeAndConsume(req AccessRequest) (AccessDecision, error) {
	unlock := lockVaultStatePath(h.store.paths.StatePath)
	defer unlock()

	if err := h.refreshStateUnlocked(); err != nil {
		return AccessDecision{}, err
	}

	decision := h.authorizeCurrent(req)
	if !decision.Allowed {
		return decision, nil
	}

	consumed := h.consumeOnceGrantsForAuthorizedRequest(req)
	if !consumed {
		return decision, nil
	}
	if err := h.persistUnlocked(); err != nil {
		return AccessDecision{}, err
	}
	h.appendGrantConsumeAudit(req)
	return decision, nil
}

func (h *Handle) refreshStateUnlocked() error {
	envelope, err := h.store.readEnvelopeStrict()
	if err != nil {
		return err
	}
	state, err := readStateFn(h.vaultKey, envelope.Data)
	if err != nil {
		return fmt.Errorf("decrypt state: %w", err)
	}
	h.state = state
	return nil
}

func (h *Handle) consumeOnceGrantsForAuthorizedRequest(req AccessRequest) bool {
	now := h.store.now()
	consumed := false
	if req.Operation == OperationList || req.Operation == OperationRun || req.Operation == OperationInject || req.Operation == OperationWriteEnv || req.Operation == OperationCapture {
		if h.consumeProjectLeaseForRequest(req, now) {
			consumed = true
		}
	}
	if req.Operation == OperationRun || req.Operation == OperationInject || req.Operation == OperationWriteEnv || req.Operation == OperationCapture {
		if h.consumeSecretGrantForRequest(req, now) {
			consumed = true
		}
	}
	if req.Operation == OperationWriteEnv {
		if h.consumeConvenienceGrantForRequest(req, now) {
			consumed = true
		}
	}
	return consumed
}

func (h *Handle) consumeProjectLeaseForRequest(req AccessRequest, now time.Time) bool {
	key := leaseKey(req.BindingID, req.SessionToken)
	lease, ok := h.state.ProjectLeases[key]
	if !ok || lease.Scope != GrantOnce || !grantIsActive(lease.Scope, lease.ExpiresAt, lease.RevokedAt, lease.UsedAt, now) {
		return false
	}
	lease.UsedAt = &now
	h.state.ProjectLeases[key] = lease
	return true
}

func (h *Handle) consumeSecretGrantForRequest(req AccessRequest, now time.Time) bool {
	if strings.TrimSpace(req.ItemName) == "" {
		return false
	}
	key := secretGrantKey(req.BindingID, req.SessionToken, req.ItemName)
	grant, ok := h.state.SecretGrants[key]
	if !ok || grant.Scope != GrantOnce || !grantIsActive(grant.Scope, grant.ExpiresAt, grant.RevokedAt, grant.UsedAt, now) {
		return false
	}
	grant.UsedAt = &now
	h.state.SecretGrants[key] = grant
	return true
}

func (h *Handle) consumeConvenienceGrantForRequest(req AccessRequest, now time.Time) bool {
	key := convenienceGrantKey(req.BindingID, req.DestinationPath, req.Aliases)
	grant, ok := h.state.ConvenienceGrants[key]
	if !ok || grant.Scope != GrantOnce || !grantIsActive(grant.Scope, grant.ExpiresAt, grant.RevokedAt, grant.UsedAt, now) {
		return false
	}
	grant.UsedAt = &now
	h.state.ConvenienceGrants[key] = grant
	return true
}

func (h *Handle) appendGrantConsumeAudit(req AccessRequest) {
	h.store.appendAuditBestEffort("grant.authorize.consume", "user", map[string]any{
		"binding_id": req.BindingID,
		"operation":  req.Operation,
		"item":       req.ItemName,
	})
}

func (h *Handle) authorizeCurrent(req AccessRequest) AccessDecision {
	if req.Policy == "" {
		req.Policy = PolicyAuto
	}

	if req.Operation == OperationList {
		if !h.projectLeaseActive(req.BindingID, req.SessionToken) {
			return AccessDecision{RequiresPrompt: true, Reason: "project_lease_required", Requirement: AccessRequirementProjectLease}
		}
		return AccessDecision{Allowed: true, Reason: "scoped_listing_allowed"}
	}

	if req.Operation == OperationCapture && req.CreatingNew {
		if !h.projectLeaseActive(req.BindingID, req.SessionToken) {
			return AccessDecision{RequiresPrompt: true, Reason: "project_lease_required", Requirement: AccessRequirementProjectLease}
		}
		return AccessDecision{RequiresPrompt: true, Reason: "write_grant_required", Requirement: AccessRequirementWriteGrant}
	}

	if req.Operation == OperationWriteEnv && (strings.TrimSpace(req.DestinationPath) != "" || len(req.Aliases) > 0) {
		if !h.projectLeaseActive(req.BindingID, req.SessionToken) {
			return AccessDecision{RequiresPrompt: true, Reason: "project_and_convenience_approval_required", Requirement: AccessRequirementProjectAndConvenience}
		}
		if !h.convenienceGrantActive(req.BindingID, req.DestinationPath, req.Aliases) {
			return AccessDecision{RequiresPrompt: true, Reason: "convenience_approval_required", Requirement: AccessRequirementConvenience}
		}
	}

	if req.Operation == OperationRun || req.Operation == OperationInject || req.Operation == OperationWriteEnv || req.Operation == OperationCapture {
		if !h.projectLeaseActive(req.BindingID, req.SessionToken) {
			return AccessDecision{RequiresPrompt: true, Reason: "project_lease_required", Requirement: AccessRequirementProjectLease}
		}
		switch req.Policy {
		case PolicyAuto:
			return AccessDecision{Allowed: true, Reason: "auto_secret_allowed"}
		case PolicySession:
			if h.secretGrantActive(req.BindingID, req.SessionToken, req.ItemName) {
				return AccessDecision{Allowed: true, Reason: "session_secret_allowed"}
			}
			return AccessDecision{RequiresPrompt: true, Reason: "secret_session_grant_required", Requirement: AccessRequirementSecretGrant}
		case PolicyAccess:
			if h.secretGrantWindowActive(req.BindingID, req.SessionToken, req.ItemName) {
				return AccessDecision{Allowed: true, Reason: "access_window_override_allowed"}
			}
			if h.secretGrantActive(req.BindingID, req.SessionToken, req.ItemName) {
				return AccessDecision{Allowed: true, Reason: "access_secret_allowed"}
			}
			return AccessDecision{RequiresPrompt: true, Reason: "access_secret_prompt_required", Requirement: AccessRequirementSecretGrant}
		default:
			return AccessDecision{RequiresPrompt: true, Reason: "unknown_policy", Requirement: AccessRequirementUnsupported}
		}
	}

	return AccessDecision{RequiresPrompt: true, Reason: "unsupported_operation", Requirement: AccessRequirementUnsupported}
}

func (h *Handle) projectLeaseActive(bindingID string, sessionToken string) bool {
	lease, ok := h.state.ProjectLeases[leaseKey(bindingID, sessionToken)]
	return ok && grantIsActive(lease.Scope, lease.ExpiresAt, lease.RevokedAt, lease.UsedAt, h.store.now())
}

func (h *Handle) secretGrantActive(bindingID string, sessionToken string, itemName string) bool {
	grant, ok := h.state.SecretGrants[secretGrantKey(bindingID, sessionToken, itemName)]
	return ok && grantIsActive(grant.Scope, grant.ExpiresAt, grant.RevokedAt, grant.UsedAt, h.store.now())
}

func (h *Handle) secretGrantWindowActive(bindingID string, sessionToken string, itemName string) bool {
	grant, ok := h.state.SecretGrants[secretGrantKey(bindingID, sessionToken, itemName)]
	if !ok || !grant.RelaxedByWindow {
		return false
	}
	return grantIsActive(grant.Scope, grant.ExpiresAt, grant.RevokedAt, grant.UsedAt, h.store.now())
}

func (h *Handle) convenienceGrantActive(bindingID string, destinationPath string, resolvedSet []string) bool {
	grant, ok := h.state.ConvenienceGrants[convenienceGrantKey(bindingID, destinationPath, resolvedSet)]
	return ok && grantIsActive(grant.Scope, grant.ExpiresAt, grant.RevokedAt, grant.UsedAt, h.store.now())
}

func (h *Handle) mutationGrantActive(bindingID string, sessionToken string, itemName string, action SecretMutationAction) bool {
	grant, ok := h.state.MutationGrants[mutationGrantKey(bindingID, sessionToken, itemName, action)]
	if !ok || !grantIsActive(grant.Scope, grant.ExpiresAt, grant.RevokedAt, grant.UsedAt, h.store.now()) {
		return false
	}
	return h.projectLeaseActive(bindingID, sessionToken)
}

func grantIsActive(scope GrantScope, expiresAt *time.Time, revokedAt *time.Time, usedAt *time.Time, now time.Time) bool {
	if revokedAt != nil {
		return false
	}
	if scope == GrantOnce && usedAt != nil {
		return false
	}
	if expiresAt != nil && now.After(*expiresAt) {
		return false
	}
	return true
}

func computeExpiry(now time.Time, scope GrantScope, ttl time.Duration) (*time.Time, error) {
	switch scope {
	case GrantOnce, GrantSession:
		return nil, nil
	case GrantWindow:
		if ttl <= 0 {
			return nil, fmt.Errorf("window grants require a positive ttl")
		}
		expires := now.Add(ttl)
		return &expires, nil
	default:
		return nil, fmt.Errorf("unsupported grant scope %q", scope)
	}
}

func leaseKey(bindingID string, sessionToken string) string {
	return bindingID + "|" + sessionToken
}

func secretGrantKey(bindingID string, sessionToken string, itemName string) string {
	return bindingID + "|" + sessionToken + "|" + itemName
}

func convenienceGrantKey(bindingID string, destinationPath string, resolvedSet []string) string {
	return bindingID + "|" + hashString(destinationPath) + "|" + hashResolvedSet(resolvedSet)
}

func plaintextGrantKey(sessionToken string, itemName string, action PlaintextAction) string {
	return sessionToken + "|" + itemName + "|" + string(action)
}

func mutationGrantKey(bindingID string, sessionToken string, itemName string, action SecretMutationAction) string {
	return bindingID + "|" + sessionToken + "|" + itemName + "|" + string(action)
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

func hashResolvedSet(values []string) string {
	identities := append([]string(nil), values...)
	slices.Sort(identities)
	return hashString(strings.Join(identities, "\n"))
}
