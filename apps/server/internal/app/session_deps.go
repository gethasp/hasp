package app

import (
	"context"
	"io"

	"github.com/gethasp/hasp/apps/server/internal/app/sessionops"
	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/app/vaultops"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// defaultSessionDeps builds a sessionops.Deps wired to the package-level seam
// vars. Each closure reads the current value of its seam var at call time, so
// test overrides propagate transparently through the sessionops handlers.
func defaultSessionDeps() sessionops.Deps {
	return sessionops.Deps{
		OpenVault:            openVaultHandleFn,
		CanonicalProjectRoot: appCanonicalProjectRootFn,
		EnsureProjectBinding: func(ctx context.Context, handle *store.Handle, root string) error {
			// Use ensureProjectBinding (auto-adopt) which silently succeeds for
			// non-git repos, matching the original sessionOpenCommand behaviour.
			_, _, _, err := ensureProjectBinding(ctx, handle, root)
			return err
		},
		GetItem:                    secretGetItemFn,
		RenderJSONOrHuman:          renderJSONOrHuman,
		RenderSimpleAction:         renderSimpleAction,
		IsHelpArg:                  isHelpArg,
		PrintHelpTopic:             printHelpTopic,
		ParsePlaintextAction:       parsePlaintextAction,
		ParseGrantScope:            parseGrantScope,
		RenderSessionOpenResult:    renderSessionOpenResult,
		RenderSessionResolveResult: renderSessionResolveResult,
		ExpandUserPath:             expandUserPath,
		NewStarter: func() (sessionops.Starter, error) {
			// *runtimeStarter satisfies sessionops.Starter via structural typing.
			return newRuntimeStarterFn()
		},
		GlobalJSON: func(ctx context.Context) bool {
			return globalFlagsFromContext(ctx).json
		},
		GrantOps: func() vaultops.GrantOpsDeps {
			d := defaultVaultGrantOpsDeps()
			return vaultops.GrantOpsDeps{
				RevokeAllGrants:          d.RevokeAllGrants,
				DisableConvenienceUnlock: d.DisableConvenienceUnlock,
			}
		},
		DefaultLocalDeps: func() sessionops.LocalDeps {
			ld := defaultSessionLocalDeps()
			return sessionops.LocalDeps{
				Approve:   ld.Approve,
				UseGrant:  ld.UseGrant,
				LocalUser: ld.LocalUser,
			}
		},
		DefaultConfirmPlaintextGrantDeps: func() sessionops.ConfirmPlaintextGrantDeps {
			cd := defaultConfirmPlaintextGrantDeps()
			return sessionops.ConfirmPlaintextGrantDeps{
				GOOS:      cd.GOOS,
				Command:   cd.Command,
				UnderTest: cd.UnderTest,
			}
		},
		GlobalColorOptions: func(ctx context.Context, stdout io.Writer) sessionops.ColorOptions {
			gf := globalFlagsFromContext(ctx)
			return sessionops.ColorOptions{
				Interactive: ui.IsInteractiveWriter(stdout),
				Disable:     gf.noColor,
				Quiet:       gf.quiet,
				Verbose:     gf.verbose,
			}
		},
	}
}
