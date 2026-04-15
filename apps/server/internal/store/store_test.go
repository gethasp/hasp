package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/paths"
)

type memoryKeyring struct {
	values map[string]string
}

func newMemoryKeyring() *memoryKeyring {
	return &memoryKeyring{values: map[string]string{}}
}

func (m *memoryKeyring) Set(_ context.Context, service string, account string, value string) error {
	m.values[service+"|"+account] = value
	return nil
}

func (m *memoryKeyring) Get(service string, account string) (string, error) {
	value, ok := m.values[service+"|"+account]
	if !ok {
		return "", ErrKeyringUnavailable
	}
	return value, nil
}

func (m *memoryKeyring) Delete(service string, account string) error {
	delete(m.values, service+"|"+account)
	return nil
}

func TestInitOpenAndCRUDItems(t *testing.T) {
	store := newTestStore(t)

	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	kv, err := handle.UpsertItem("api_token", ItemKindKV, []byte("secret-value"), ItemMetadata{Policy: PolicySession})
	if err != nil {
		t.Fatalf("upsert kv item: %v", err)
	}
	if kv.Kind != ItemKindKV {
		t.Fatalf("item kind = %q", kv.Kind)
	}

	fileItem, err := handle.UpsertItem("service_account", ItemKindFile, []byte("{\"client_email\":\"ops@gethasp.com\"}"), ItemMetadata{Tags: []string{"json"}})
	if err != nil {
		t.Fatalf("upsert file item: %v", err)
	}
	if fileItem.Kind != ItemKindFile {
		t.Fatalf("item kind = %q", fileItem.Kind)
	}

	found, err := handle.GetItem("api_token")
	if err != nil {
		t.Fatalf("get item: %v", err)
	}
	if string(found.Value) != "secret-value" {
		t.Fatalf("item value = %q", string(found.Value))
	}

	items := handle.ListItems()
	if len(items) != 2 {
		t.Fatalf("list items = %d, want 2", len(items))
	}

	if err := handle.DeleteItem("api_token"); err != nil {
		t.Fatalf("delete item: %v", err)
	}
	if _, err := handle.GetItem("api_token"); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("expected item not found after delete, got %v", err)
	}
}

func TestUpsertItemUpdateAndValidationPaths(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := handle.UpsertItem("", ItemKindKV, []byte("value"), ItemMetadata{}); err == nil {
		t.Fatal("expected empty name error")
	}
	if _, err := handle.UpsertItem("api_token", ItemKind("bogus"), []byte("value"), ItemMetadata{}); err == nil {
		t.Fatal("expected invalid kind error")
	}
	item, err := handle.UpsertItem("api_token", ItemKindKV, []byte("value-one"), ItemMetadata{})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	updated, err := handle.UpsertItem("api_token", ItemKindKV, []byte("value-two"), ItemMetadata{})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if updated.ID != item.ID || string(updated.Value) != "value-two" {
		t.Fatalf("unexpected updated item: %+v", updated)
	}
}

func TestUpsertAndDeletePropagatePersistFailure(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	origPersist := persistEnvelope
	defer func() { persistEnvelope = origPersist }()
	persistEnvelope = func(*Handle) error { return fmt.Errorf("persist fail") }
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("value"), ItemMetadata{}); err == nil {
		t.Fatal("expected upsert persist failure")
	}
	if err := handle.DeleteItem("missing"); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("expected item-not-found, got %v", err)
	}
}

func TestPersistFailsOnMalformedEnvelope(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := os.WriteFile(store.paths.StatePath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write malformed vault: %v", err)
	}
	if err := handle.persist(); err == nil {
		t.Fatal("expected persist failure")
	}

	handle.vaultKey = []byte("short")
	if err := handle.persist(); err == nil {
		t.Fatal("expected persist sealState failure")
	}
}

func TestWrongPasswordFails(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	if _, err := store.OpenWithPassword(context.Background(), "wrong"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected invalid password error, got %v", err)
	}
}

func TestInitRejectsEmptyPasswordAndExistingVault(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), ""); err == nil {
		t.Fatal("expected empty password init failure")
	}
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	if err := store.Init(context.Background(), "correct horse battery staple"); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("expected vault exists error, got %v", err)
	}
}

func TestConvenienceUnlockUsesKeyring(t *testing.T) {
	keyring := newMemoryKeyring()
	store := newTestStoreWithKeyring(t, keyring)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}

	reopened, err := store.OpenWithConvenienceUnlock(context.Background())
	if err != nil {
		t.Fatalf("open with convenience unlock: %v", err)
	}
	if _, err := reopened.UpsertItem("staging_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("write via convenience unlock: %v", err)
	}
}

func TestOpenWithConvenienceUnlockFailsWhenUnavailable(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	if _, err := store.OpenWithConvenienceUnlock(context.Background()); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected keyring unavailable, got %v", err)
	}
}

func TestOpenWithConvenienceUnlockFailsOnBadWrap(t *testing.T) {
	keyring := newMemoryKeyring()
	store := newTestStoreWithKeyring(t, keyring)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}
	envelope, err := store.readEnvelope()
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	envelope.Header.ConvenienceWrap = &sealedBlob{Nonce: "AA==", Ciphertext: "AA=="}
	if err := store.writeEnvelopeFile(envelope); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
	if _, err := store.OpenWithConvenienceUnlock(context.Background()); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected unavailable on bad wrap, got %v", err)
	}
}

func TestEnableConvenienceUnlockFailsWithoutKeyring(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected keyring unavailable, got %v", err)
	}
}

func TestStoreWritesAuditEvents(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("secret-value"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if err := handle.DeleteItem("api_token"); err != nil {
		t.Fatalf("delete item: %v", err)
	}
	if err := store.audit.Verify(); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	if _, err := os.Stat(store.paths.AuditPath); err != nil {
		t.Fatalf("expected audit log file: %v", err)
	}
}

func TestNewWithNilKeyringFallsBackToUnsupported(t *testing.T) {
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)
	store, err := New(nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if _, ok := store.keyring.(unsupportedKeyring); !ok {
		t.Fatal("expected unsupported keyring fallback")
	}
}

func TestNewAndInitErrorPaths(t *testing.T) {
	lockStoreSeams(t)
	origResolve := resolvePathsFn
	origAudit := newAuditLogFn
	origMkdir := mkdirAllFn
	origStat := statFn
	origRandom := randomBytesFn
	origDeriveWrap := deriveWrapFn
	origSeal := sealBytesFn
	defer func() {
		resolvePathsFn = origResolve
		newAuditLogFn = origAudit
		mkdirAllFn = origMkdir
		statFn = origStat
		randomBytesFn = origRandom
		deriveWrapFn = origDeriveWrap
		sealBytesFn = origSeal
	}()

	resolvePathsFn = func() (paths.Paths, error) { return paths.Paths{}, fmt.Errorf("resolve fail") }
	if _, err := New(nil); err == nil {
		t.Fatal("expected resolve paths failure")
	}

	resolvePathsFn = origResolve
	newAuditLogFn = func() (*audit.Log, error) { return nil, fmt.Errorf("audit fail") }
	if _, err := New(nil); err == nil {
		t.Fatal("expected audit init failure")
	}

	newAuditLogFn = origAudit
	store := newTestStore(t)
	mkdirAllFn = func(string, os.FileMode) error { return fmt.Errorf("mkdir fail") }
	if err := store.Init(context.Background(), "correct horse battery staple"); err == nil {
		t.Fatal("expected mkdir failure")
	}

	mkdirAllFn = origMkdir
	statFn = func(string) (os.FileInfo, error) { return nil, fmt.Errorf("stat fail") }
	if err := store.Init(context.Background(), "correct horse battery staple"); err == nil {
		t.Fatal("expected stat failure")
	}

	statFn = origStat
	randomBytesFn = func(int) ([]byte, error) { return nil, fmt.Errorf("random fail") }
	if err := store.Init(context.Background(), "correct horse battery staple"); err == nil {
		t.Fatal("expected random failure")
	}

	randomBytesFn = origRandom
	deriveWrapFn = func(string) (kdfSpec, []byte, error) { return kdfSpec{}, nil, fmt.Errorf("derive fail") }
	if err := store.Init(context.Background(), "correct horse battery staple"); err == nil {
		t.Fatal("expected derive failure")
	}

	deriveWrapFn = origDeriveWrap
	sealBytesFn = func([]byte, []byte) (sealedBlob, error) { return sealedBlob{}, fmt.Errorf("seal fail") }
	if err := store.Init(context.Background(), "correct horse battery staple"); err == nil {
		t.Fatal("expected seal failure")
	}
}

func TestOpenWithPasswordAndConvenienceUnlockFailurePaths(t *testing.T) {
	lockStoreSeams(t)
	keyring := newMemoryKeyring()
	store := newTestStoreWithKeyring(t, keyring)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if err := handle.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}

	origDeriveSpec := deriveSpecFn
	origOpen := openBytesFn
	origReadState := readStateFn
	defer func() {
		deriveSpecFn = origDeriveSpec
		openBytesFn = origOpen
		readStateFn = origReadState
	}()

	deriveSpecFn = func(string, kdfSpec) ([]byte, error) { return nil, fmt.Errorf("derive fail") }
	if _, err := store.OpenWithPassword(context.Background(), "correct horse battery staple"); err == nil {
		t.Fatal("expected derive spec failure")
	}
	deriveSpecFn = origDeriveSpec

	openBytesFn = func([]byte, sealedBlob) ([]byte, error) { return nil, fmt.Errorf("open fail") }
	if _, err := store.OpenWithPassword(context.Background(), "correct horse battery staple"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected invalid password wrapper, got %v", err)
	}
	if _, err := store.OpenWithConvenienceUnlock(context.Background()); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected convenience unavailable wrapper, got %v", err)
	}

	openBytesFn = origOpen
	readStateFn = func([]byte, sealedBlob) (persistedState, error) { return persistedState{}, fmt.Errorf("decode fail") }
	if _, err := store.OpenWithPassword(context.Background(), "correct horse battery staple"); err == nil {
		t.Fatal("expected readState failure")
	}
	if _, err := store.OpenWithConvenienceUnlock(context.Background()); err == nil {
		t.Fatal("expected convenience readState failure")
	}
}

func TestItemHelpersExerciseNilStateDeletedEntriesAndNilAudit(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	handle := &Handle{
		store: store,
		state: persistedState{},
	}

	origPersist := persistEnvelope
	defer func() { persistEnvelope = origPersist }()
	persistEnvelope = func(*Handle) error { return nil }

	item, err := handle.UpsertItem("api_token", ItemKindKV, []byte("value"), ItemMetadata{})
	if err != nil {
		t.Fatalf("upsert into nil item map: %v", err)
	}
	deletedAt := store.now()
	handle.state.Items["deleted"] = Item{Name: "deleted", DeletedAt: &deletedAt}
	listed := handle.ListItems()
	if len(listed) != 1 || listed[0].ID != item.ID {
		t.Fatalf("unexpected listed items: %+v", listed)
	}

	handle.store.audit = nil
	if err := handle.DeleteItem("api_token"); err != nil {
		t.Fatalf("delete with nil audit: %v", err)
	}
}

func TestInitAndConvenienceUnlockAdditionalFailurePaths(t *testing.T) {
	store := newTestStore(t)
	lockedDir := filepath.Join(store.paths.HomeDir, "locked")
	if err := os.MkdirAll(lockedDir, 0o700); err != nil {
		t.Fatalf("mkdir locked dir: %v", err)
	}
	if err := os.Chmod(lockedDir, 0o500); err != nil {
		t.Fatalf("chmod locked dir: %v", err)
	}
	defer func() {
		_ = os.Chmod(lockedDir, 0o700)
	}()
	store.paths.StatePath = filepath.Join(lockedDir, "vault.json")
	if err := store.Init(context.Background(), "correct horse battery staple"); err == nil {
		t.Fatal("expected write envelope failure")
	}

	store = newTestStore(t)
	if _, err := store.OpenWithConvenienceUnlock(context.Background()); !errors.Is(err, ErrVaultNotInitialized) {
		t.Fatalf("expected missing vault error for convenience unlock, got %v", err)
	}

	handle := &Handle{store: newTestStoreWithKeyring(t, newMemoryKeyring()), vaultKey: make([]byte, keyLength)}
	if err := handle.EnableConvenienceUnlock(context.Background()); !errors.Is(err, ErrVaultNotInitialized) {
		t.Fatalf("expected missing vault error, got %v", err)
	}

	keyring := newMemoryKeyring()
	store = newTestStoreWithKeyring(t, keyring)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	opened, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	origRandom := randomBytesFn
	origSeal := sealBytesFn
	defer func() {
		randomBytesFn = origRandom
		sealBytesFn = origSeal
	}()

	randomBytesFn = func(int) ([]byte, error) { return nil, fmt.Errorf("random fail") }
	if err := opened.EnableConvenienceUnlock(context.Background()); err == nil {
		t.Fatal("expected convenience random failure")
	}

	randomBytesFn = origRandom
	sealBytesFn = func([]byte, []byte) (sealedBlob, error) { return sealedBlob{}, fmt.Errorf("seal fail") }
	if err := opened.EnableConvenienceUnlock(context.Background()); err == nil {
		t.Fatal("expected convenience seal failure")
	}

	sealBytesFn = origSeal
	if err := opened.EnableConvenienceUnlock(context.Background()); err != nil {
		t.Fatalf("enable convenience unlock: %v", err)
	}
	if err := keyring.Delete(keyringService, store.keyringAccount()); err != nil {
		t.Fatalf("delete keyring entry: %v", err)
	}
	if _, err := store.OpenWithConvenienceUnlock(context.Background()); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("expected missing keyring entry error, got %v", err)
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return newTestStoreWithKeyring(t, unsupportedKeyring{})
}

func newTestStoreWithKeyring(t *testing.T, keyring Keyring) *Store {
	t.Helper()
	baseDir := t.TempDir()
	t.Setenv(paths.EnvHome, baseDir)
	store, err := New(keyring)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return store
}
