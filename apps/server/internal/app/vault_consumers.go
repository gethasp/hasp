package app

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/vaultops"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

// vaultGrantOpsDeps wires the store-handle operations that vault-lock,
// vault forget-device, and session revoke --all need to drop saved grants
// and convenience unlock state. Tests build a local instance to inject
// failure paths without touching package-level vars.
type vaultGrantOpsDeps struct {
	RevokeAllGrants          func(handle *store.Handle) (int, error)
	DisableConvenienceUnlock func(handle *store.Handle, ctx context.Context) (bool, error)
}

func defaultVaultGrantOpsDeps() vaultGrantOpsDeps {
	return vaultGrantOpsDeps{
		RevokeAllGrants: (*store.Handle).RevokeAllGrants,
		DisableConvenienceUnlock: func(h *store.Handle, ctx context.Context) (bool, error) {
			return h.DisableConvenienceUnlock(ctx)
		},
	}
}

// loadNewMasterPassword reads the new master password from the environment.
// Used by vault rekey to obtain the replacement credential.
func loadNewMasterPassword() (string, error) {
	password := strings.TrimSpace(os.Getenv("HASP_NEW_MASTER_PASSWORD"))
	if password == "" {
		return "", errors.New("HASP_NEW_MASTER_PASSWORD must be set to the new master password")
	}
	return password, nil
}

// ── Vault command shims ───────────────────────────────────────────────────────
//
// These shims preserve the package-app function signatures that existing tests
// call directly. Each one delegates to vaultops.VaultCommand via defaultVaultDeps()
// (or a locally-customised Deps). Zero behaviour change.

func vaultCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	deps := defaultVaultDeps()
	if s != nil {
		deps.NewStarter = func() (vaultops.Starter, error) { return s, nil }
	}
	return vaultops.VaultCommand(ctx, deps, args, nil, stdout, io.Discard)
}

func vaultLockCommand(ctx context.Context, args []string, stdout io.Writer, s starter) error {
	deps := defaultVaultDeps()
	if s != nil {
		deps.NewStarter = func() (vaultops.Starter, error) { return s, nil }
	}
	return vaultops.VaultCommand(ctx, deps, append([]string{"lock"}, args...), nil, stdout, io.Discard)
}

func vaultLockCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, s starter, grantDeps vaultGrantOpsDeps) error {
	deps := defaultVaultDeps()
	if s != nil {
		deps.NewStarter = func() (vaultops.Starter, error) { return s, nil }
	}
	deps.GrantOps = func() vaultops.GrantOpsDeps {
		return vaultops.GrantOpsDeps{
			RevokeAllGrants:          grantDeps.RevokeAllGrants,
			DisableConvenienceUnlock: grantDeps.DisableConvenienceUnlock,
		}
	}
	return vaultops.VaultCommand(ctx, deps, append([]string{"lock"}, args...), nil, stdout, io.Discard)
}

func vaultForgetDeviceCommand(ctx context.Context, args []string, stdout io.Writer) error {
	return vaultops.VaultCommand(ctx, defaultVaultDeps(), append([]string{"forget-device"}, args...), nil, stdout, io.Discard)
}

func vaultForgetDeviceCommandWithDeps(ctx context.Context, args []string, stdout io.Writer, grantDeps vaultGrantOpsDeps) error {
	deps := defaultVaultDeps()
	deps.GrantOps = func() vaultops.GrantOpsDeps {
		return vaultops.GrantOpsDeps{
			RevokeAllGrants:          grantDeps.RevokeAllGrants,
			DisableConvenienceUnlock: grantDeps.DisableConvenienceUnlock,
		}
	}
	return vaultops.VaultCommand(ctx, deps, append([]string{"forget-device"}, args...), nil, stdout, io.Discard)
}
