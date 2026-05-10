package store

import (
	"slices"
	"strings"
)

func (h *Handle) ListProjectLeases() []ProjectLease {
	out := make([]ProjectLease, 0, len(h.state.ProjectLeases))
	for _, grant := range h.state.ProjectLeases {
		out = append(out, grant)
	}
	slices.SortFunc(out, func(a, b ProjectLease) int {
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

func (h *Handle) ListSecretGrants() []SecretGrant {
	out := make([]SecretGrant, 0, len(h.state.SecretGrants))
	for _, grant := range h.state.SecretGrants {
		out = append(out, grant)
	}
	slices.SortFunc(out, func(a, b SecretGrant) int {
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

func (h *Handle) ListPlaintextGrants() []PlaintextGrant {
	out := make([]PlaintextGrant, 0, len(h.state.PlaintextGrants))
	for _, grant := range h.state.PlaintextGrants {
		out = append(out, grant)
	}
	slices.SortFunc(out, func(a, b PlaintextGrant) int {
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

func (h *Handle) ListMutationGrants() []MutationGrant {
	out := make([]MutationGrant, 0, len(h.state.MutationGrants))
	for _, grant := range h.state.MutationGrants {
		out = append(out, grant)
	}
	slices.SortFunc(out, func(a, b MutationGrant) int {
		return strings.Compare(a.ID, b.ID)
	})
	return out
}
