package app

import (
	"context"

	"github.com/gethasp/hasp/apps/server/internal/app/vaultops"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// defaultVaultDeps builds a vaultops.Deps wired to the package-level seam
// vars. Each closure reads the current value of its seam var at call time, so
// test overrides of openVaultHandleFn, newRuntimeStarterFn, etc. propagate
// transparently through the vaultops handlers.
func defaultVaultDeps() vaultops.Deps {
	return vaultops.Deps{
		OpenVaultHandle: func(ctx context.Context) (*store.Handle, error) {
			return openVaultHandleFn(ctx)
		},
		NewStarter: func() (vaultops.Starter, error) {
			// *runtimeStarter satisfies vaultops.Starter via structural typing
			// (it has a Connect method with the right signature).
			return newRuntimeStarterFn()
		},
		LoadMasterPassword:    loadMasterPassword,
		LoadNewMasterPassword: loadNewMasterPassword,
		RenderJSONOrHuman:     renderJSONOrHuman,
		RenderSimpleAction:    renderSimpleAction,
		IsHelpArg:             isHelpArg,
		PrintHelpTopic:        printHelpTopic,
		GlobalJSON: func(ctx context.Context) bool {
			return globalFlagsFromContext(ctx).json
		},
	}
}
