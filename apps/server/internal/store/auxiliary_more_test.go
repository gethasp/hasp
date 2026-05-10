package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

func TestBackupAdditionalFailurePaths(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	origAudit := newAuditLogFn
	origRandom := randomBytesFn
	origDeriveWrap := deriveWrapFn
	origSeal := sealBytesFn
	origMarshal := jsonMarshalFn
	origMarshalIndent := jsonMarshalIndentFn
	defer func() {
		newAuditLogFn = origAudit
		randomBytesFn = origRandom
		deriveWrapFn = origDeriveWrap
		sealBytesFn = origSeal
		jsonMarshalFn = origMarshal
		jsonMarshalIndentFn = origMarshalIndent
	}()

	newAuditLogFn = func() (*audit.Log, error) { return nil, fmt.Errorf("audit init fail") }
	if _, err := handle.ExportBackup(context.Background(), filepath.Join(t.TempDir(), "backup.json"), "backup-passphrase"); err == nil {
		t.Fatal("expected backup audit init failure")
	}
	newAuditLogFn = origAudit

	if err := os.WriteFile(store.paths.AuditPath, []byte("{bad json\n"), 0o600); err != nil {
		t.Fatalf("write malformed audit log: %v", err)
	}
	if _, err := handle.ExportBackup(context.Background(), filepath.Join(t.TempDir(), "backup.json"), "backup-passphrase"); err == nil {
		t.Fatal("expected backup checkpoint failure")
	}
	if err := os.Remove(store.paths.AuditPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove malformed audit log: %v", err)
	}

	deriveWrapFn = func(string) (kdfSpec, []byte, error) { return kdfSpec{}, nil, fmt.Errorf("derive fail") }
	if _, err := handle.ExportBackup(context.Background(), filepath.Join(t.TempDir(), "backup.json"), "backup-passphrase"); err == nil {
		t.Fatal("expected export derive failure")
	}
	deriveWrapFn = origDeriveWrap

	sealBytesFn = func([]byte, []byte) (sealedBlob, error) { return sealedBlob{}, fmt.Errorf("seal fail") }
	if _, err := handle.ExportBackup(context.Background(), filepath.Join(t.TempDir(), "backup.json"), "backup-passphrase"); err == nil {
		t.Fatal("expected export seal failure")
	}
	sealBytesFn = origSeal

	jsonMarshalFn = func(any) ([]byte, error) { return nil, fmt.Errorf("marshal fail") }
	if _, err := handle.ExportBackup(context.Background(), filepath.Join(t.TempDir(), "backup.json"), "backup-passphrase"); err == nil {
		t.Fatal("expected export payload marshal failure")
	}
	jsonMarshalFn = origMarshal

	jsonMarshalIndentFn = func(any, string, string) ([]byte, error) { return nil, fmt.Errorf("marshal indent fail") }
	if _, err := handle.ExportBackup(context.Background(), filepath.Join(t.TempDir(), "backup.json"), "backup-passphrase"); err == nil {
		t.Fatal("expected export file marshal failure")
	}
	jsonMarshalIndentFn = origMarshalIndent

	outputDir := filepath.Join(t.TempDir(), "backup-dir")
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		t.Fatalf("mkdir output dir: %v", err)
	}
	if _, err := handle.ExportBackup(context.Background(), outputDir, "backup-passphrase"); err == nil {
		t.Fatal("expected export write failure")
	}

	backupPath := exportBackupFixture(t)
	restoreStore := newTestStore(t)

	if _, err := restoreStore.RestoreBackup(context.Background(), filepath.Join(t.TempDir(), "missing.backup"), "backup-passphrase", "restored-password"); err == nil {
		t.Fatal("expected restore read failure")
	}

	file := readBackupFixture(t, backupPath)
	file.KDF.Salt = "%%%"
	writeBackupFixture(t, backupPath, file)
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err == nil {
		t.Fatal("expected restore KDF decode failure")
	}

	backupPath = exportBackupFixture(t)
	stripVaultKeyFromBackupFixture(t, backupPath)
	randomBytesFn = func(int) ([]byte, error) { return nil, fmt.Errorf("random fail") }
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err == nil {
		t.Fatal("expected restore random failure")
	}
	randomBytesFn = origRandom

	deriveWrapFn = func(string) (kdfSpec, []byte, error) { return kdfSpec{}, nil, fmt.Errorf("derive fail") }
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err == nil {
		t.Fatal("expected restore derive failure")
	}
	deriveWrapFn = origDeriveWrap

	sealBytesFn = func([]byte, []byte) (sealedBlob, error) { return sealedBlob{}, fmt.Errorf("seal fail") }
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err == nil {
		t.Fatal("expected restore seal failure")
	}
	sealBytesFn = origSeal

	blocker := filepath.Join(t.TempDir(), "blocked-parent")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	restoreStore.paths.StatePath = filepath.Join(blocker, "vault.json")
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err == nil {
		t.Fatal("expected restore write-envelope failure")
	}

	restoreStore = newTestStore(t)
	newAuditLogFn = func() (*audit.Log, error) { return nil, fmt.Errorf("audit init fail") }
	if _, err := restoreStore.RestoreBackup(context.Background(), backupPath, "backup-passphrase", "restored-password"); err == nil {
		t.Fatal("expected restore trailing audit init failure")
	}
}

func TestBindingAdditionalBranches(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	origAbs := filepathAbsFn
	defer func() { filepathAbsFn = origAbs }()
	filepathAbsFn = func(string) (string, error) { return "", fmt.Errorf("abs fail") }
	if _, err := CanonicalProjectRoot(context.Background(), ""); err == nil {
		t.Fatal("expected canonical project root failure")
	}
	if _, err := handle.UpsertBinding(context.Background(), "", map[string]string{}, PolicySession, false); err == nil {
		t.Fatal("expected upsert binding root failure")
	}
	if _, err := handle.BindItemAlias(context.Background(), "", "api_token"); err == nil {
		t.Fatal("expected bind alias root failure")
	}
	if _, _, err := handle.ResolveBindingView(context.Background(), ""); err == nil {
		t.Fatal("expected resolve binding view root failure")
	}
	if err := handle.DeleteBinding(context.Background(), ""); err == nil {
		t.Fatal("expected delete binding root failure")
	}
	filepathAbsFn = origAbs

	handle.state.Bindings = nil
	projectRoot := t.TempDir()
	binding, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{" secret_01 ": " api_token "}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding into nil map: %v", err)
	}
	if binding.Aliases["secret_01"] != "api_token" {
		t.Fatalf("expected trimmed alias mapping, got %+v", binding.Aliases)
	}

	root, err := CanonicalProjectRoot(context.Background(), projectRoot)
	if err != nil {
		t.Fatalf("canonicalize project root: %v", err)
	}
	handle.state.Bindings[root] = Binding{
		ID:                   binding.ID,
		CanonicalRoot:        root,
		Aliases:              nil,
		DefaultCapturePolicy: PolicySession,
	}
	if alias, err := handle.BindItemAlias(context.Background(), projectRoot, "api_token"); err != nil || alias != "secret_01" {
		t.Fatalf("bind alias with nil alias map: alias=%q err=%v", alias, err)
	}
	if _, err := handle.BindItemAlias(context.Background(), projectRoot, "missing_item"); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("expected missing item bind error, got %v", err)
	}

	manifestRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(manifestRoot, manifestFilename), []byte(`{"default_capture_policy":"access","references":[{"alias":"","item":"skip"},{"alias":" ","item":"skip"},{"alias":"secret_09","item":"api_token"}]}`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	resolved, visible, err := handle.ResolveBindingView(context.Background(), manifestRoot)
	if err != nil {
		t.Fatalf("resolve manifest-backed binding view: %v", err)
	}
	if resolved.DefaultCapturePolicy != PolicyAccess || len(visible) != 1 || visible[0].Alias != "secret_09" {
		t.Fatalf("unexpected resolved binding view: %+v visible=%+v", resolved, visible)
	}

	badManifestRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(badManifestRoot, manifestFilename), 0o700); err != nil {
		t.Fatalf("mkdir bad manifest path: %v", err)
	}
	if _, _, err := handle.ResolveBindingView(context.Background(), badManifestRoot); err == nil {
		t.Fatal("expected manifest read error")
	}

	missingItemRoot := t.TempDir()
	if _, err := handle.UpsertBinding(context.Background(), missingItemRoot, map[string]string{"secret_77": "missing_item"}, PolicySession, false); err != nil {
		t.Fatalf("upsert missing-item binding: %v", err)
	}
	if _, _, err := handle.ResolveBindingView(context.Background(), missingItemRoot); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("expected resolve binding view item-not-found, got %v", err)
	}

	symlinkTarget := t.TempDir()
	symlinkPath := filepath.Join(t.TempDir(), "project-link")
	if err := os.Symlink(symlinkTarget, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	wantRoot, err := filepath.EvalSymlinks(symlinkTarget)
	if err != nil {
		t.Fatalf("eval symlink target: %v", err)
	}
	if got := normalizeRoot(symlinkPath); got != wantRoot {
		t.Fatalf("normalizeRoot symlink = %q, want %q", got, wantRoot)
	}
	missingPath := filepath.Join(t.TempDir(), "missing", "root")
	if got := normalizeRoot(missingPath); got != filepath.Clean(missingPath) {
		t.Fatalf("normalizeRoot missing path = %q, want %q", got, filepath.Clean(missingPath))
	}
}

func TestImportEnvelopeAuthorizeAndCaptureAdditionalBranches(t *testing.T) {
	lockStoreSeams(t)
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{Policy: PolicySession}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}

	if _, err := handle.ImportEnvFile(filepath.Join(t.TempDir(), "missing.env")); err == nil {
		t.Fatal("expected missing env file error")
	}
	longEnvPath := filepath.Join(t.TempDir(), "long.env")
	if err := os.WriteFile(longEnvPath, []byte("TOO_LONG="+strings.Repeat("a", 70*1024)), 0o600); err != nil {
		t.Fatalf("write long env: %v", err)
	}
	if _, err := handle.ImportEnvFile(longEnvPath); err == nil {
		t.Fatal("expected scanner error for oversized env line")
	}

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("BROKEN_LINE\n"), 0o600); err != nil {
		t.Fatalf("write broken env: %v", err)
	}
	if _, err := handle.importEnvFile(context.Background(), envPath, ImportOptions{}); err == nil {
		t.Fatal("expected wrapped importEnvFile failure")
	}

	validEnvPath := filepath.Join(t.TempDir(), ".valid.env")
	if err := os.WriteFile(validEnvPath, []byte("NEW_TOKEN=xyz\n"), 0o600); err != nil {
		t.Fatalf("write valid env: %v", err)
	}
	origPersist := persistEnvelope
	defer func() { persistEnvelope = origPersist }()
	persistEnvelope = func(*Handle) error { return fmt.Errorf("persist fail") }
	if _, err := handle.ImportEnvFile(validEnvPath); err == nil {
		t.Fatal("expected import env upsert failure")
	}
	persistEnvelope = origPersist

	origAbs := filepathAbsFn
	defer func() { filepathAbsFn = origAbs }()
	persistEnvelope = func(*Handle) error { return nil }
	filepathAbsFn = func(string) (string, error) { return "", fmt.Errorf("abs fail") }
	if _, err := handle.importEnvFile(context.Background(), validEnvPath, ImportOptions{ProjectRoot: ".", BindToProject: true}); err == nil {
		t.Fatal("expected importEnvFile bind failure")
	}
	persistEnvelope = origPersist

	jsonPath := filepath.Join(t.TempDir(), "service-account.json")
	if err := os.WriteFile(jsonPath, []byte(`{"client_email":"ops@gethasp.com"}`), 0o600); err != nil {
		t.Fatalf("write json file: %v", err)
	}
	if _, err := handle.ImportJSONCredential(filepath.Join(t.TempDir(), "missing.json"), "name"); err == nil {
		t.Fatal("expected missing JSON credential error")
	}
	badJSONPath := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(badJSONPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write malformed json: %v", err)
	}
	if _, err := handle.importJSONFile(context.Background(), badJSONPath, ImportOptions{}); err == nil {
		t.Fatal("expected importJSONFile credential failure")
	}
	persistEnvelope = func(*Handle) error { return nil }
	if _, err := handle.importJSONFile(context.Background(), jsonPath, ImportOptions{ProjectRoot: ".", BindToProject: true}); err == nil {
		t.Fatal("expected importJSONFile bind failure")
	}
	persistEnvelope = origPersist
	filepathAbsFn = origAbs

	if _, err := handle.ResolveReference(context.Background(), t.TempDir(), "api_token"); !errors.Is(err, ErrReferenceNotFound) {
		t.Fatalf("expected repo-scoped reference lookup to reject raw item names, got %v", err)
	}
	filepathAbsFn = func(string) (string, error) { return "", fmt.Errorf("abs fail") }
	if _, err := handle.ResolveReference(context.Background(), ".", "api_token"); err == nil {
		t.Fatal("expected ResolveReference root failure")
	}
	filepathAbsFn = origAbs
	if _, err := handle.ResolveReferenceItem(context.Background(), t.TempDir(), "missing"); !errors.Is(err, ErrReferenceNotFound) {
		t.Fatalf("expected resolve reference item failure, got %v", err)
	}

	statePath := store.paths.StatePath
	if _, err := handle.store.readEnvelope(); err != nil {
		t.Fatalf("read envelope baseline: %v", err)
	}
	origMarshal := jsonMarshalFn
	origMarshalIndent := jsonMarshalIndentFn
	defer func() {
		jsonMarshalFn = origMarshal
		jsonMarshalIndentFn = origMarshalIndent
	}()
	store.paths.StatePath = t.TempDir()
	if _, err := handle.store.readEnvelope(); err == nil {
		t.Fatal("expected generic readEnvelope failure")
	}
	store.paths.StatePath = statePath

	lockedParent := filepath.Join(t.TempDir(), "locked")
	if err := os.MkdirAll(lockedParent, 0o700); err != nil {
		t.Fatalf("mkdir locked parent: %v", err)
	}
	if err := os.Chmod(lockedParent, 0o500); err != nil {
		t.Fatalf("chmod locked parent: %v", err)
	}
	defer func() { _ = os.Chmod(lockedParent, 0o700) }()
	store.paths.StatePath = filepath.Join(lockedParent, "vault.json")
	if err := store.writeEnvelopeFile(fileEnvelope{Header: envelopeHeader{Version: 1}}); err == nil {
		t.Fatal("expected writeEnvelopeFile temp write failure")
	}
	store.paths.StatePath = statePath

	jsonMarshalIndentFn = func(any, string, string) ([]byte, error) { return nil, fmt.Errorf("marshal indent fail") }
	if err := store.writeEnvelopeFile(fileEnvelope{Header: envelopeHeader{Version: 1}}); err == nil {
		t.Fatal("expected writeEnvelopeFile encode failure")
	}
	jsonMarshalIndentFn = origMarshalIndent

	jsonMarshalFn = func(any) ([]byte, error) { return nil, fmt.Errorf("marshal fail") }
	if _, err := sealState(make([]byte, keyLength), persistedState{}); err == nil {
		t.Fatal("expected sealState marshal failure")
	}
	jsonMarshalFn = origMarshal

	if _, err := readState([]byte("short"), sealedBlob{}); err == nil {
		t.Fatal("expected readState openBytes failure")
	}
	rawState := []byte(`{}`)
	blob, err := sealBytes(make([]byte, keyLength), rawState)
	if err != nil {
		t.Fatalf("seal raw state: %v", err)
	}
	state, err := readState(make([]byte, keyLength), blob)
	if err != nil {
		t.Fatalf("read raw state: %v", err)
	}
	if state.Items == nil || state.Bindings == nil || state.ProjectLeases == nil || state.SecretGrants == nil || state.ConvenienceGrants == nil || state.PlaintextGrants == nil || state.MutationGrants == nil {
		t.Fatalf("expected nil maps initialized, got %+v", state)
	}

	now := time.Now()
	past := now.Add(-time.Minute)
	if active := grantIsActive(GrantSession, nil, &now, nil, now); active {
		t.Fatal("expected revoked grant inactive")
	}
	if active := grantIsActive(GrantOnce, nil, nil, &now, now); active {
		t.Fatal("expected used once grant inactive")
	}
	if active := grantIsActive(GrantWindow, &past, nil, nil, now); active {
		t.Fatal("expected expired grant inactive")
	}
	if _, err := computeExpiry(now, GrantScope("bad"), time.Second); err == nil {
		t.Fatal("expected unsupported scope expiry failure")
	}
	if _, err := computeExpiry(now, GrantWindow, 0); err == nil {
		t.Fatal("expected non-positive window ttl failure")
	}
	if handle.secretGrantWindowActive("missing", "session-token", "api_token") {
		t.Fatal("expected missing window grant inactive")
	}
	handle.state.SecretGrants[secretGrantKey("binding", "session-token", "api_token")] = SecretGrant{
		BindingID:       "binding",
		ItemName:        "api_token",
		SessionToken:    "session-token",
		Scope:           GrantWindow,
		RelaxedByWindow: false,
	}
	if handle.secretGrantWindowActive("binding", "session-token", "api_token") {
		t.Fatal("expected non-relaxed window grant inactive")
	}

	projectRoot := t.TempDir()
	binding, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{"secret_01": "api_token"}, PolicySession, false)
	if err != nil {
		t.Fatalf("upsert binding: %v", err)
	}
	grantProjectLease := func(sessionToken string) {
		handle.state.ProjectLeases[leaseKey(binding.ID, sessionToken)] = ProjectLease{
			ID:           "lease-" + sessionToken,
			BindingID:    binding.ID,
			SessionToken: sessionToken,
			Scope:        GrantSession,
		}
	}
	grantSecretUse := func(sessionToken string, relaxed bool) {
		handle.state.SecretGrants[secretGrantKey(binding.ID, sessionToken, "api_token")] = SecretGrant{
			ID:              "secret-" + sessionToken,
			BindingID:       binding.ID,
			ItemName:        "api_token",
			SessionToken:    sessionToken,
			Scope:           GrantSession,
			RelaxedByWindow: relaxed,
		}
	}
	decision := handle.Authorize(AccessRequest{
		Operation:    OperationCapture,
		BindingID:    binding.ID,
		SessionToken: "session-token",
		CreatingNew:  true,
	})
	if !decision.RequiresPrompt || decision.Reason != "project_lease_required" {
		t.Fatalf("unexpected capture auth without lease: %+v", decision)
	}
	grantProjectLease("session-token")
	decision = handle.Authorize(AccessRequest{
		Operation:    OperationCapture,
		BindingID:    binding.ID,
		SessionToken: "session-token",
		CreatingNew:  true,
	})
	if !decision.RequiresPrompt || decision.Reason != "write_grant_required" {
		t.Fatalf("unexpected capture auth with lease: %+v", decision)
	}
	decision = handle.Authorize(AccessRequest{
		Operation:    OperationCapture,
		BindingID:    binding.ID,
		SessionToken: "missing-lease",
		ItemName:     "api_token",
		Policy:       PolicySession,
	})
	if !decision.RequiresPrompt || decision.Reason != "project_lease_required" {
		t.Fatalf("unexpected capture auth without general lease: %+v", decision)
	}
	decision = handle.Authorize(AccessRequest{
		Operation:       OperationWriteEnv,
		BindingID:       binding.ID,
		SessionToken:    "session-token",
		ItemName:        "api_token",
		Policy:          PolicySession,
		DestinationPath: "/tmp/.env",
		Aliases:         []string{"secret_01"},
	})
	if !decision.RequiresPrompt || decision.Reason != "convenience_approval_required" {
		t.Fatalf("unexpected write-env auth without convenience grant: %+v", decision)
	}
	decision = handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: "session-token",
		ItemName:     "api_token",
		Policy:       PolicyAuto,
	})
	if !decision.Allowed || decision.Reason != "auto_secret_allowed" {
		t.Fatalf("unexpected policy auto decision: %+v", decision)
	}
	grantSecretUse("session-token", true)
	decision = handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: "session-token",
		ItemName:     "api_token",
		Policy:       PolicyAccess,
	})
	if !decision.Allowed || decision.Reason != "access_window_override_allowed" {
		t.Fatalf("unexpected relaxed access decision: %+v", decision)
	}
	grantProjectLease("access-prompt-token")
	grantSecretUse("access-grant-token", false)
	grantProjectLease("access-grant-token")
	decision = handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: "access-grant-token",
		ItemName:     "api_token",
		Policy:       PolicyAccess,
	})
	if !decision.Allowed || decision.Reason != "access_secret_allowed" {
		t.Fatalf("unexpected access secret decision: %+v", decision)
	}
	decision = handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: "access-prompt-token",
		ItemName:     "api_token",
		Policy:       PolicyAccess,
	})
	if !decision.RequiresPrompt || decision.Reason != "access_secret_prompt_required" {
		t.Fatalf("unexpected access prompt decision: %+v", decision)
	}
	decision = handle.Authorize(AccessRequest{
		Operation:    OperationRun,
		BindingID:    binding.ID,
		SessionToken: "session-token",
		ItemName:     "api_token",
		Policy:       SecretPolicy("bogus"),
	})
	if !decision.RequiresPrompt || decision.Reason != "unknown_policy" {
		t.Fatalf("unexpected unknown policy decision: %+v", decision)
	}
	decision = handle.Authorize(AccessRequest{Operation: Operation("bogus")})
	if !decision.RequiresPrompt || decision.Reason != "unsupported_operation" {
		t.Fatalf("unexpected unsupported operation decision: %+v", decision)
	}

	if _, err := handle.Capture(context.Background(), projectRoot, "", ItemKindKV, []byte("value"), false); err == nil {
		t.Fatal("expected capture upsert failure")
	}
	persistEnvelope = func(*Handle) error { return nil }
	filepathAbsFn = func(string) (string, error) { return "", fmt.Errorf("abs fail") }
	if _, err := handle.Capture(context.Background(), ".", "captured_secret", ItemKindKV, []byte("value"), true); err == nil {
		t.Fatal("expected capture bind failure")
	}
	persistEnvelope = origPersist
}

func exportBackupFixture(t *testing.T) string {
	t.Helper()
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init fixture store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open fixture store: %v", err)
	}
	if _, err := handle.UpsertItem("fixture_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert fixture item: %v", err)
	}
	path := filepath.Join(t.TempDir(), "fixture.backup.json")
	if _, err := handle.ExportBackup(context.Background(), path, "backup-passphrase"); err != nil {
		t.Fatalf("export fixture backup: %v", err)
	}
	return path
}

func readBackupFixture(t *testing.T, path string) BackupFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read backup fixture: %v", err)
	}
	var file BackupFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode backup fixture: %v", err)
	}
	return file
}

func writeBackupFixture(t *testing.T, path string, file BackupFile) {
	t.Helper()
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("encode backup fixture: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write backup fixture: %v", err)
	}
}

func stripVaultKeyFromBackupFixture(t *testing.T, path string) {
	t.Helper()
	file := readBackupFixture(t, path)
	key, err := deriveFromSpec("backup-passphrase", file.KDF)
	if err != nil {
		t.Fatalf("derive fixture wrap key: %v", err)
	}
	plaintext, err := openBytes(key, file.Payload)
	if err != nil {
		t.Fatalf("open fixture payload: %v", err)
	}
	var payload backupPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatalf("decode fixture payload: %v", err)
	}
	payload.VaultKey = nil
	plaintext, err = json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode fixture payload: %v", err)
	}
	sealed, err := sealBytes(key, plaintext)
	if err != nil {
		t.Fatalf("seal fixture payload: %v", err)
	}
	file.Payload = sealed
	file.Integrity = integrityDigest(plaintext)
	writeBackupFixture(t, path, file)
}
