package app

import (
	"context"
	"io"

	"github.com/gethasp/hasp/apps/server/internal/app/runtimeops"
	"github.com/gethasp/hasp/apps/server/internal/runtime"
)

// defaultRuntimeDeps builds a runtimeops.Deps wired to the package-level seam
// vars. Each closure reads the current value of its seam var at call time, so
// test overrides propagate transparently through the runtimeops handlers.
func defaultRuntimeDeps() runtimeops.Deps {
	return runtimeops.Deps{
		OpenVault:          openVaultHandleFn,
		NewVaultStore:      newVaultStoreFn,
		TerminalColumns:    terminalColumnsFn,
		RenderJSONOrHuman:  renderJSONOrHuman,
		WriteJSONResponse:  writeJSONResponse,
		RenderBackupResult: renderBackupResult,
		RenderStatusHuman: func(stdout io.Writer, reply runtime.StatusResponse, _ func() int) error {
			// renderStatusHuman in runtime_consumers.go reads terminalColumnsFn directly.
			return renderStatusHuman(stdout, reply)
		},
		RenderPingJSONOrHuman: renderPingJSONOrHuman,
		RenderNotRunning:      renderNotRunning,
		ConnectIfRunning: func(ctx context.Context, s runtimeops.Starter) *runtime.Client {
			// *runtimeStarter satisfies the package-private starter interface via
			// structural typing (same method set). Type-assert so connectIfRunning
			// can accept it.
			priv, ok := s.(starter)
			if !ok || priv == nil {
				return nil
			}
			return connectIfRunning(ctx, priv)
		},
		NewStarter: func() (runtimeops.Starter, error) {
			// *runtimeStarter satisfies runtimeops.Starter via structural typing.
			return newRuntimeStarterFn()
		},
		EnsureProjectBinding: ensureProjectBinding,
		ReadPassphrase:       readPassphrase,
		ExpandUserPath:       expandUserPath,
		LoadMasterPassword:   loadMasterPassword,
		IsHelpArg:            isHelpArg,
		PrintHelpTopic:       printHelpTopic,
		GlobalJSON: func(ctx context.Context) bool {
			return globalFlagsFromContext(ctx).json
		},
		ErrArgvPassphrase:     errArgvPassphrase,
		ErrArgvMasterPassword: errArgvMasterPassword,
		NewInternalError: func(msg string) error {
			return newAppError(errCodeInternal, msg)
		},
	}
}
