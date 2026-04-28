package sessionops

import (
	"context"

	"github.com/gethasp/hasp/apps/server/internal/app/vaultops"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// defaultGrantOpsDeps returns the production GrantOpsDeps that delegates
// directly to the store methods. Used when Deps.GrantOps is not wired.
func defaultGrantOpsDeps() vaultops.GrantOpsDeps {
	return vaultops.GrantOpsDeps{
		RevokeAllGrants: (*store.Handle).RevokeAllGrants,
		DisableConvenienceUnlock: func(h *store.Handle, ctx context.Context) (bool, error) {
			return h.DisableConvenienceUnlock(ctx)
		},
	}
}

// resolveGrantOps returns GrantOpsDeps from deps.GrantOps if wired, or
// defaultGrantOpsDeps() as the fallback.
func resolveGrantOps(deps Deps) vaultops.GrantOpsDeps {
	if deps.GrantOps != nil {
		return deps.GrantOps()
	}
	return defaultGrantOpsDeps()
}
