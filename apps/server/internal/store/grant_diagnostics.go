package store

// OnceGrantConsumed reports the relevant grant's recorded use, without returning it.
// Call after authorization so the handle contains the state that denied the request.
func (h *Handle) OnceGrantConsumed(req AccessRequest, requirement AccessRequirement) bool {
	switch requirement {
	case AccessRequirementProjectLease, AccessRequirementProjectAndConvenience:
		g := h.state.ProjectLeases[leaseKey(req.BindingID, req.SessionToken)]
		return g.Scope == GrantOnce && g.UsedAt != nil
	case AccessRequirementSecretGrant:
		g := h.state.SecretGrants[secretGrantKey(req.BindingID, req.SessionToken, req.ItemName)]
		return g.Scope == GrantOnce && g.UsedAt != nil
	case AccessRequirementConvenience:
		g := h.state.ConvenienceGrants[convenienceGrantKey(req.BindingID, req.DestinationPath, req.Aliases)]
		return g.Scope == GrantOnce && g.UsedAt != nil
	default:
		return false
	}
}
