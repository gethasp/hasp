package app

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestWriteEnvAuthorizesSecretsUnderWriteEnvOperation(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)
	outputPath := filepath.Join(t.TempDir(), ".env")

	deps := defaultExecDeps()
	deps.AuthorizeItem = func(handle *store.Handle, bindingID, sessionToken string, item store.Item, op store.Operation, projScope, secScope store.GrantScope, window time.Duration) (store.Item, error) {
		if op != store.OperationWriteEnv {
			return store.Item{}, fmt.Errorf("authorize item op = %s, want %s", op, store.OperationWriteEnv)
		}
		return item, nil
	}

	if err := writeEnvCommandWithDeps(
		context.Background(),
		writeEnvArgs(projectRoot, outputPath, "--force"),
		io.Discard,
		io.Discard,
		&fakeStarter{},
		deps,
	); err != nil {
		t.Fatalf("write-env should authorize secret delivery under write-env semantics: %v", err)
	}
}

func TestWriteEnvConvenienceGrantUsesResolvedReferences(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)
	outputPath := filepath.Join(t.TempDir(), ".env")

	deps := defaultExecDeps()
	deps.GrantConvenience = func(handle *store.Handle, bindingID, sessionToken, dest string, items []string, principal string, scope store.GrantScope, window time.Duration) (store.ConvenienceGrant, error) {
		if dest != outputPath {
			return store.ConvenienceGrant{}, fmt.Errorf("grant convenience destination = %q, want %q", dest, outputPath)
		}
		if !slices.Equal(items, []string{"secret_01"}) {
			return store.ConvenienceGrant{}, fmt.Errorf("grant convenience refs = %v, want [secret_01]", items)
		}
		return store.ConvenienceGrant{ID: "grant", Scope: scope}, nil
	}

	if err := writeEnvCommandWithDeps(
		context.Background(),
		writeEnvArgs(projectRoot, outputPath, "--force"),
		io.Discard,
		io.Discard,
		&fakeStarter{},
		deps,
	); err != nil {
		t.Fatalf("write-env should preserve resolved reference context for convenience grants: %v", err)
	}
}
