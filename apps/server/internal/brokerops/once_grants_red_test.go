package brokerops

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestAuthorizeReferenceDeniesSecondUseOfOnceProjectLease(t *testing.T) {
	vaultStore, bindingID, projectRoot := setupBrokeropsGrantFixture(t)

	first := openBrokeropsGrantHandle(t, vaultStore)
	if _, err := AuthorizeReference(
		context.Background(),
		first,
		bindingID,
		projectRoot,
		"session-token",
		"secret_01",
		store.OperationRun,
		store.GrantOnce,
		store.GrantSession,
		"",
		time.Minute,
		"",
	); err != nil {
		t.Fatalf("first once project use: %v", err)
	}

	second := openBrokeropsGrantHandle(t, vaultStore)
	if _, err := AuthorizeReference(
		context.Background(),
		second,
		bindingID,
		projectRoot,
		"session-token",
		"secret_01",
		store.OperationRun,
		"",
		"",
		"",
		time.Minute,
		"",
	); err == nil {
		t.Fatal("expected second use of a once project lease to fail closed")
	}
}

func TestAuthorizeReferenceDeniesSecondUseOfOnceSecretGrant(t *testing.T) {
	vaultStore, bindingID, projectRoot := setupBrokeropsGrantFixture(t)

	first := openBrokeropsGrantHandle(t, vaultStore)
	if _, err := AuthorizeReference(
		context.Background(),
		first,
		bindingID,
		projectRoot,
		"session-token",
		"secret_01",
		store.OperationRun,
		store.GrantSession,
		store.GrantOnce,
		"",
		time.Minute,
		"",
	); err != nil {
		t.Fatalf("first once secret use: %v", err)
	}

	second := openBrokeropsGrantHandle(t, vaultStore)
	if _, err := AuthorizeReference(
		context.Background(),
		second,
		bindingID,
		projectRoot,
		"session-token",
		"secret_01",
		store.OperationRun,
		"",
		"",
		"",
		time.Minute,
		"",
	); err == nil {
		t.Fatal("expected second use of a once secret grant to fail closed")
	}
}

func TestAuthorizeReferenceConcurrentOnceSecretGrantAllowsOneContender(t *testing.T) {
	vaultStore, bindingID, projectRoot := setupBrokeropsGrantFixture(t)

	setup := openBrokeropsGrantHandle(t, vaultStore)
	if _, err := setup.GrantProjectLease(bindingID, "session-token", store.GrantSession, 0); err != nil {
		t.Fatalf("grant shared project lease: %v", err)
	}

	var successes atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup

	for range 2 {
		handle := openBrokeropsGrantHandle(t, vaultStore)
		wg.Add(1)
		go func(handle *store.Handle) {
			defer wg.Done()
			<-start
			if _, err := AuthorizeReference(
				context.Background(),
				handle,
				bindingID,
				projectRoot,
				"session-token",
				"secret_01",
				store.OperationRun,
				"",
				store.GrantOnce,
				"",
				time.Minute,
				"",
			); err == nil {
				successes.Add(1)
			}
		}(handle)
	}

	close(start)
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("concurrent once secret authorization successes = %d, want 1", got)
	}
}

func setupBrokeropsGrantFixture(t *testing.T) (*store.Store, string, string) {
	t.Helper()

	t.Setenv(paths.EnvHome, t.TempDir())
	vaultStore, err := store.New(nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vaultStore.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle := openBrokeropsGrantHandle(t, vaultStore)
	item, err := handle.UpsertItem("api_token", store.ItemKindKV, []byte("secret-value"), store.ItemMetadata{Policy: store.PolicySession})
	if err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	projectRoot := t.TempDir()
	binding, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": item.Name}, store.PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	return vaultStore, binding.ID, projectRoot
}

func openBrokeropsGrantHandle(t *testing.T, vaultStore *store.Store) *store.Handle {
	t.Helper()
	handle, err := vaultStore.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return handle
}
