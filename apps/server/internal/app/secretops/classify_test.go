package secretops

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestClassifyValidatesArgumentsAndRequiresOperatorCheck(t *testing.T) {
	ctx := context.Background()
	for _, args := range [][]string{{"classify"}, {"classify", "--invalid"}, {"classify", "TOKEN", "--classification", "public"}} {
		if err := SecretCommand(ctx, Deps{}, args, nil, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	args := []string{"classify", "TOKEN", "--classification", "configuration"}
	deps, _ := fullSecretDeps(t)
	if err := SecretCommand(ctx, deps, args, nil, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "operator check is unavailable") {
		t.Fatalf("missing operator check: %v", err)
	}
	want := errors.New("vault unavailable")
	deps.OpenVault = func(context.Context) (*store.Handle, error) { return nil, want }
	if err := SecretCommand(ctx, deps, args, nil, io.Discard, io.Discard); !errors.Is(err, want) {
		t.Fatalf("vault failure: %v", err)
	}
}
