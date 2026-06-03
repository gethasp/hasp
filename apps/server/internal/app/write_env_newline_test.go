package app

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// TestRejectLineDeliveryNewline pins the helper guarding line-based delivery
// formats against newline injection (hasp-zqzv / hasp-g84c).
func TestRejectLineDeliveryNewline(t *testing.T) {
	if err := rejectLineDeliveryNewline("API_KEY", []byte("single-line-value")); err != nil {
		t.Fatalf("single-line value should be accepted: %v", err)
	}
	for _, bad := range []string{"a\nINJECT=evil", "a\rINJECT=evil", "trailing\n"} {
		if err := rejectLineDeliveryNewline("API_KEY", []byte(bad)); err == nil {
			t.Fatalf("value %q with a line break should be rejected", bad)
		}
	}
}

// TestWriteEnvRejectsNewlineInValue ensures write-env refuses to write a secret
// whose value contains a newline into a line-based .env/xcconfig file, where it
// would otherwise inject an extra assignment.
func TestWriteEnvRejectsNewlineInValue(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)
	outputPath := filepath.Join(t.TempDir(), ".env")

	deps := defaultExecDeps()
	deps.AuthorizeItem = func(handle *store.Handle, bindingID, sessionToken string, item store.Item, op store.Operation, projScope, secScope store.GrantScope, window time.Duration) (store.Item, error) {
		item.Value = []byte("real-value\nINJECTED = evil")
		return item, nil
	}

	err := writeEnvCommandWithDeps(
		context.Background(),
		writeEnvArgs(projectRoot, outputPath, "--force"),
		io.Discard,
		io.Discard,
		&fakeStarter{},
		deps,
	)
	if err == nil {
		t.Fatal("expected write-env to reject a newline-containing secret value")
	}
	if !strings.Contains(err.Error(), "newline") {
		t.Fatalf("expected a newline-rejection error, got: %v", err)
	}
}

// TestWriteEnvConsumesConvenienceGrant pins hasp-hi88: write-env must consume the
// one-time convenience grant (keyed by output path + reference set) so a single
// approval can't be replayed across later write-env invocations.
func TestWriteEnvConsumesConvenienceGrant(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)
	outputPath := filepath.Join(t.TempDir(), ".env")

	deps := defaultExecDeps()
	var gotDest string
	var gotRefs []string
	called := 0
	deps.ConsumeConvenienceGrant = func(handle *store.Handle, bindingID, dest string, items []string) error {
		called++
		gotDest = dest
		gotRefs = items
		return nil
	}

	if err := writeEnvCommandWithDeps(
		context.Background(),
		writeEnvArgs(projectRoot, outputPath, "--force"),
		io.Discard,
		io.Discard,
		&fakeStarter{},
		deps,
	); err != nil {
		t.Fatalf("write-env: %v", err)
	}
	if called != 1 {
		t.Fatalf("expected ConsumeConvenienceGrant called once, got %d", called)
	}
	if gotDest != outputPath {
		t.Fatalf("consume destination = %q, want %q", gotDest, outputPath)
	}
	if len(gotRefs) == 0 {
		t.Fatal("expected a non-empty reference set passed to consume")
	}
}

func TestWriteEnvPropagatesConvenienceGrantConsumeFailure(t *testing.T) {
	lockAppSeams(t)
	projectRoot := bootstrapVaultForOverwriteTests(t)
	outputPath := filepath.Join(t.TempDir(), ".env")

	deps := defaultExecDeps()
	deps.ConsumeConvenienceGrant = func(*store.Handle, string, string, []string) error {
		return errors.New("consume convenience grant failed")
	}

	err := writeEnvCommandWithDeps(
		context.Background(),
		writeEnvArgs(projectRoot, outputPath, "--force"),
		io.Discard,
		io.Discard,
		&fakeStarter{},
		deps,
	)
	if err == nil || !strings.Contains(err.Error(), "consume convenience grant failed") {
		t.Fatalf("expected convenience grant consume failure, got %v", err)
	}
}
