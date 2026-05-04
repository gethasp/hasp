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
	if req.Policy == "" {
		req.Policy = PolicyAuto
	}

	if req.Operation == OperationList {
		if !h.projectLeaseActive(req.BindingID, req.SessionToken) {
			return AccessDecision{RequiresPrompt: true, Reason: "project_lease_required"}
		}
		return AccessDecision{Allowed: true, Reason: "scoped_listing_allowed"}
	}

	if req.Operation == OperationCapture && req.CreatingNew {
		if !h.projectLeaseActive(req.BindingID, req.SessionToken) {
			return AccessDecision{RequiresPrompt: true, Reason: "project_lease_required"}
		}
		return AccessDecision{RequiresPrompt: true, Reason: "write_grant_required"}
	}

	if req.Operation == OperationWriteEnv {
		if !h.projectLeaseActive(req.BindingID, req.SessionToken) {
			return AccessDecision{RequiresPrompt: true, Reason: "project_and_convenience_approval_required"}
		}
		if !h.convenienceGrantActive(req.BindingID, req.DestinationPath, req.Aliases) {
			return AccessDecision{RequiresPrompt: true, Reason: "convenience_approval_required"}
		}
	}

	if req.Operation == OperationRun || req.Operation == OperationInject || req.Operation == OperationWriteEnv || req.Operation == OperationCapture {
		if !h.projectLeaseActive(req.BindingID, req.SessionToken) {
			return AccessDecision{RequiresPrompt: true, Reason: "project_lease_required"}
		}
		switch req.Policy {
		case PolicyAuto:
			return AccessDecision{Allowed: true, Reason: "auto_secret_allowed"}
		case PolicySession:
			if h.secretGrantActive(req.BindingID, req.SessionToken, req.ItemName) {
				return AccessDecision{Allowed: true, Reason: "session_secret_allowed"}
			}
			return AccessDecision{RequiresPrompt: true, Reason: "secret_session_grant_required"}
		case PolicyAccess:
			if h.secretGrantWindowActive(req.BindingID, req.SessionToken, req.ItemName) {
				return AccessDecision{Allowed: true, Reason: "access_window_override_allowed"}
			}
			if h.secretGrantActive(req.BindingID, req.SessionToken, req.ItemName) {
				return AccessDecision{Allowed: true, Reason: "access_secret_allowed"}
			}
			return AccessDecision{RequiresPrompt: true, Reason: "access_secret_prompt_required"}
		default:
			return AccessDecision{RequiresPrompt: true, Reason: "unknown_policy"}
		}
	}

	return AccessDecision{RequiresPrompt: true, Reason: "unsupported_operation"}
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
