package vaultops

import (
	"context"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// defaultGrantOpsDeps returns the production GrantOpsDeps that delegates
// directly to the store methods. Used when Deps.GrantOps is not wired.
func defaultGrantOpsDeps() GrantOpsDeps {
	return GrantOpsDeps{
		RevokeAllGrants: (*store.Handle).RevokeAllGrants,
		DisableConvenienceUnlock: func(h *store.Handle, ctx context.Context) (bool, error) {
			return h.DisableConvenienceUnlock(ctx)
		},
	}
}

// resolveGrantOpsDeps returns the GrantOpsDeps from deps if wired, or
// defaultGrantOpsDeps() as the fallback.
func resolveGrantOpsDeps(deps Deps) GrantOpsDeps {
	if deps.GrantOps != nil {
		return deps.GrantOps()
	}
	return defaultGrantOpsDeps()
}

// cliPair constructs a [2]string label/value pair for rendering helpers.
func cliPair(label string, value string) [2]string {
	return [2]string{label, value}
}
