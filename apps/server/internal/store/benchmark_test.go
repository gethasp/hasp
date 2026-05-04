package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
)

func BenchmarkOpenWithPassword(b *testing.B) {
	store := newBenchmarkStore(b)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		b.Fatalf("init store: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
		if err != nil {
			b.Fatalf("open store: %v", err)
		}
		if handle == nil {
			b.Fatal("expected handle")
		}
	}
}

func BenchmarkUpsertItemPersist(b *testing.B) {
	store := newBenchmarkStore(b)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		b.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		b.Fatalf("open store: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := handle.UpsertItem(fmt.Sprintf("item-%d", i), ItemKindKV, []byte("value"), ItemMetadata{}); err != nil {
			b.Fatalf("upsert item: %v", err)
		}
	}
}

func BenchmarkAuthorizeSessionGrant(b *testing.B) {
	store := newBenchmarkStore(b)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		b.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		b.Fatalf("open store: %v", err)
	}
	item, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{Policy: PolicySession})
	if err != nil {
		b.Fatalf("upsert item: %v", err)
	}
	binding, err := handle.UpsertBinding(context.Background(), b.TempDir(), map[string]string{"secret_01": item.Name}, PolicySession, false)
	if err != nil {
		b.Fatalf("upsert binding: %v", err)
	}
	if _, err := handle.GrantProjectLease(binding.ID, "session-token", GrantWindow, time.Minute); err != nil {
		b.Fatalf("grant project lease: %v", err)
	}
	if _, err := handle.GrantSecretUse(binding.ID, "session-token", item.Name, GrantSession, 0, false); err != nil {
		b.Fatalf("grant secret use: %v", err)
	}
	request := AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: "session-token",
		ItemName:     item.Name,
		Policy:       PolicySession,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision := handle.Authorize(request)
		if !decision.Allowed {
			b.Fatalf("unexpected denied decision: %+v", decision)
		}
	}
}

func newBenchmarkStore(b *testing.B) *Store {
	b.Helper()
	b.Setenv(paths.EnvHome, b.TempDir())
	vaultStore, err := New(nil)
	if err != nil {
		b.Fatalf("new store: %v", err)
	}
	return vaultStore
}
