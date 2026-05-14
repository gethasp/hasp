package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

type memoryHMACKeyring struct {
	values map[string]string
	getErr error
	setErr error
}

type protectedMemoryHMACKeyring struct {
	memoryHMACKeyring
	requirements []string
}

type nativeMemoryHMACKeyring struct {
	protectedMemoryHMACKeyring
	nativeValue string
	nativeErr   error
	deleted     bool
	nativeGets  int
	genericGets int
}

func (k *protectedMemoryHMACKeyring) SetWithDesignatedRequirements(ctx context.Context, service string, account string, value string, requirements []string) error {
	k.requirements = append([]string(nil), requirements...)
	return k.Set(ctx, service, account, value)
}

func (k *nativeMemoryHMACKeyring) GetNative(service string, account string) (string, error) {
	k.nativeGets++
	if k.nativeErr != nil {
		return "", k.nativeErr
	}
	return k.nativeValue, nil
}

func (k *nativeMemoryHMACKeyring) DeleteNative(string, string) error {
	k.deleted = true
	k.nativeErr = store.KeyringItemNotFoundError{Err: errors.New("item not found")}
	k.nativeValue = ""
	return nil
}

func (k *memoryHMACKeyring) Set(_ context.Context, service string, account string, value string) error {
	if k.setErr != nil {
		return k.setErr
	}
	if k.values == nil {
		k.values = map[string]string{}
	}
	k.values[service+"/"+account] = value
	return nil
}

func (k *memoryHMACKeyring) Get(service string, account string) (string, error) {
	if k.getErr != nil {
		return "", k.getErr
	}
	value, ok := k.values[service+"/"+account]
	if !ok {
		return "", errors.New("item not found")
	}
	return value, nil
}

func (k *nativeMemoryHMACKeyring) Get(service string, account string) (string, error) {
	k.genericGets++
	return k.protectedMemoryHMACKeyring.Get(service, account)
}

func (k *memoryHMACKeyring) Delete(service string, account string) error {
	delete(k.values, service+"/"+account)
	return nil
}

func TestLoadOrCreateHMACKeyUsesExistingKey(t *testing.T) {
	account, err := HMACKeyAccount()
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	keyring := &memoryHMACKeyring{values: map[string]string{
		HMACKeyService + "/" + account: base64.StdEncoding.EncodeToString(key),
	}}

	got, err := LoadOrCreateHMACKey(context.Background(), keyring)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("key = %q, want %q", got, key)
	}
}

func TestLoadOrCreateHMACKeyCreatesMissingKey(t *testing.T) {
	account, err := HMACKeyAccount()
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	keyring := &memoryHMACKeyring{}

	key, err := LoadOrCreateHMACKey(context.Background(), keyring)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if len(key) != sha256.Size {
		t.Fatalf("key length = %d, want %d", len(key), sha256.Size)
	}
	stored, err := keyring.Get(HMACKeyService, account)
	if err != nil {
		t.Fatalf("get stored key: %v", err)
	}
	decoded, err := decodeHMACKey(stored)
	if err != nil {
		t.Fatalf("decode stored key: %v", err)
	}
	if string(decoded) != string(key) {
		t.Fatal("stored key does not match returned key")
	}
}

func TestLocalDebugHMACKeyUsesHASPHomeFile(t *testing.T) {
	if goruntime.GOOS != "darwin" {
		t.Skip("local debug HMAC file is a Darwin debug-app path")
	}
	restoreTeamID := setHMACTeamIDForTest("TEAM123456")
	t.Cleanup(restoreTeamID)
	home := t.TempDir()
	t.Setenv("HASP_HOME", home)
	keyring := &nativeMemoryHMACKeyring{
		nativeErr: errors.New("native keychain should not be used"),
	}

	key, err := LoadOrCreateHMACKey(context.Background(), keyring)
	if err != nil {
		t.Fatalf("create local debug key: %v", err)
	}
	if len(key) != sha256.Size {
		t.Fatalf("key length = %d, want %d", len(key), sha256.Size)
	}
	if keyring.nativeGets != 0 || keyring.genericGets != 0 {
		t.Fatalf("keyring was used: native=%d generic=%d", keyring.nativeGets, keyring.genericGets)
	}
	path := filepath.Join(home, localDebugHMACKeyFile)
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("stat local debug key: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("local debug key mode = %v, want 0600", info.Mode().Perm())
	}

	loaded, err := LoadProvisionedHMACKey(keyring)
	if err != nil {
		t.Fatalf("load local debug key: %v", err)
	}
	if string(loaded) != string(key) {
		t.Fatal("loaded local debug key does not match created key")
	}
}

func TestLoadOrCreateHMACKeyUsesDesignatedRequirementKeyring(t *testing.T) {
	restoreTeamID := setHMACTeamIDForTest("TEAM123")
	defer restoreTeamID()
	account, err := HMACKeyAccount()
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	keyring := &protectedMemoryHMACKeyring{}

	key, err := LoadOrCreateHMACKey(context.Background(), keyring)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if len(key) != sha256.Size {
		t.Fatalf("key length = %d, want %d", len(key), sha256.Size)
	}
	wantApp := `identifier "com.gethasp.hasp.HASP" and anchor apple generic and certificate leaf[subject.OU] = "TEAM123" and certificate 1[field.1.2.840.113635.100.6.2.6] exists`
	wantDaemon := `identifier "com.gethasp.hasp.daemon" and anchor apple generic and certificate leaf[subject.OU] = "TEAM123" and certificate 1[field.1.2.840.113635.100.6.2.6] exists`
	if len(keyring.requirements) != 2 || keyring.requirements[0] != wantApp || keyring.requirements[1] != wantDaemon {
		t.Fatalf("requirements = %#v, want app+daemon DRs", keyring.requirements)
	}
	if _, err := keyring.Get(HMACKeyService, account); err != nil {
		t.Fatalf("stored key missing: %v", err)
	}
}

func TestLoadOrCreateHMACKeyDoesNotRewriteExistingDesignatedRequirementKey(t *testing.T) {
	restoreTeamID := setHMACTeamIDForTest("TEAM123")
	defer restoreTeamID()
	account, err := HMACKeyAccount()
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	keyring := &protectedMemoryHMACKeyring{memoryHMACKeyring: memoryHMACKeyring{values: map[string]string{
		HMACKeyService + "/" + account: base64.StdEncoding.EncodeToString(key),
	}}}

	got, err := LoadOrCreateHMACKey(context.Background(), keyring)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("key = %q, want %q", got, key)
	}
	if len(keyring.requirements) != 0 {
		t.Fatalf("existing read must not rewrite keychain ACL, got %#v", keyring.requirements)
	}
}

func TestLoadHMACKeyPrefersNativeKeyringRead(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	keyring := &nativeMemoryHMACKeyring{
		nativeValue: base64.StdEncoding.EncodeToString(key),
	}

	got, err := LoadHMACKey(keyring)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("key = %q, want %q", got, key)
	}
	if keyring.nativeGets != 1 || keyring.genericGets != 0 {
		t.Fatalf("read path native=%d generic=%d, want native-only", keyring.nativeGets, keyring.genericGets)
	}
}

func TestLoadOrCreateHMACKeyCreatesOnlyOnNativeNotFound(t *testing.T) {
	restoreTeamID := setHMACTeamIDForTest("TEAM123")
	defer restoreTeamID()
	keyring := &nativeMemoryHMACKeyring{
		nativeErr: store.KeyringItemNotFoundError{Err: errors.New("item not found")},
	}

	if _, err := LoadOrCreateHMACKey(context.Background(), keyring); err != nil {
		t.Fatalf("create after native not found: %v", err)
	}
	if len(keyring.requirements) != 2 {
		t.Fatalf("expected new key to be written with DRs, got %#v", keyring.requirements)
	}
}

func TestLoadOrCreateHMACKeyDoesNotRotateOnNativeFailure(t *testing.T) {
	keyring := &nativeMemoryHMACKeyring{
		nativeErr: store.ErrKeyringUnavailable,
	}

	if _, err := LoadOrCreateHMACKey(context.Background(), keyring); err == nil || !errors.Is(err, store.ErrKeyringUnavailable) {
		t.Fatalf("expected native failure, got %v", err)
	}
	if len(keyring.requirements) != 0 {
		t.Fatalf("native failure must not write replacement key, got %#v", keyring.requirements)
	}
}

func TestStoreHMACKeyRejectsGenericKeyringOutsideTests(t *testing.T) {
	if goruntime.GOOS != "darwin" {
		t.Skip("protected HMAC keyring is macOS-only")
	}
	keyring := &memoryHMACKeyring{}
	originalArgs0 := osArgs0ForTest(t, "/usr/local/bin/hasp")
	defer originalArgs0()

	err := storeHMACKey(context.Background(), keyring, "acct", base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)))
	if err == nil || !errors.Is(err, store.ErrKeyringUnavailable) {
		t.Fatalf("expected keyring unavailable from generic keyring, got %v", err)
	}
	if _, err := keyring.Get(HMACKeyService, "acct"); err == nil {
		t.Fatal("generic keyring must not receive HTTP HMAC key outside tests")
	}
}

func TestHMACKeyFingerprintDoesNotCreateMissingKey(t *testing.T) {
	keyring := &memoryHMACKeyring{}

	if _, err := HMACKeyFingerprint(context.Background(), keyring); err == nil {
		t.Fatal("expected missing key error")
	}
	if len(keyring.values) != 0 {
		t.Fatalf("fingerprint command should not create key, got %+v", keyring.values)
	}
}

func TestLoadProvisionedHMACKeyFailsClosedWhenMissing(t *testing.T) {
	keyring := &memoryHMACKeyring{}

	if _, err := LoadProvisionedHMACKey(keyring); err == nil || !errors.Is(err, ErrHMACSecretNotProvisioned) {
		t.Fatalf("expected not provisioned error, got %v", err)
	}
	if len(keyring.values) != 0 {
		t.Fatalf("provisioned load must not create key, got %+v", keyring.values)
	}
}

func TestLoadProvisionedHMACKeyUsesExistingNativeKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	keyring := &nativeMemoryHMACKeyring{
		nativeValue: base64.StdEncoding.EncodeToString(key),
	}

	got, err := LoadProvisionedHMACKey(keyring)
	if err != nil {
		t.Fatalf("load provisioned key: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("key = %q, want %q", got, key)
	}
	if keyring.nativeGets != 1 || keyring.genericGets != 0 {
		t.Fatalf("read path native=%d generic=%d, want native-only", keyring.nativeGets, keyring.genericGets)
	}
}

func TestReinitializeHMACKeyDeletesAndRecreatesWithDesignatedRequirements(t *testing.T) {
	restoreTeamID := setHMACTeamIDForTest("TEAM123")
	defer restoreTeamID()
	keyring := &nativeMemoryHMACKeyring{
		nativeValue: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	}

	key, err := ReinitializeHMACKey(context.Background(), keyring)
	if err != nil {
		t.Fatalf("reinitialize key: %v", err)
	}
	if keyring.deleted {
		t.Fatal("reinitialize must overwrite instead of delete-first")
	}
	if len(key) != sha256.Size {
		t.Fatalf("key length = %d, want %d", len(key), sha256.Size)
	}
	if len(keyring.requirements) != 2 ||
		!strings.Contains(keyring.requirements[0], `identifier "com.gethasp.hasp.HASP"`) ||
		!strings.Contains(keyring.requirements[1], `identifier "com.gethasp.hasp.daemon"`) {
		t.Fatalf("requirements = %#v, want app+daemon DRs", keyring.requirements)
	}
}

func TestLoadOrCreateHMACKeyRejectsMalformedStoredKey(t *testing.T) {
	account, err := HMACKeyAccount()
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	keyring := &memoryHMACKeyring{values: map[string]string{
		HMACKeyService + "/" + account: base64.StdEncoding.EncodeToString([]byte("short")),
	}}

	if _, err := LoadOrCreateHMACKey(context.Background(), keyring); err == nil {
		t.Fatal("expected malformed stored key error")
	}
}

func TestLoadOrCreateHMACKeyPropagatesWriteFailure(t *testing.T) {
	keyring := &memoryHMACKeyring{setErr: store.ErrKeyringUnavailable}

	if _, err := LoadOrCreateHMACKey(context.Background(), keyring); err == nil {
		t.Fatal("expected write failure")
	}
}

func TestHMACKeyAccountIgnoresSpoofedUserEnv(t *testing.T) {
	account, err := HMACKeyAccount()
	if err != nil {
		t.Fatalf("account: %v", err)
	}
	t.Setenv("USER", "spoofed")
	spoofed, err := HMACKeyAccount()
	if err != nil {
		t.Fatalf("spoofed account: %v", err)
	}
	if spoofed != account {
		t.Fatalf("account used spoofed USER env: got %q want %q", spoofed, account)
	}
}

func TestHMACKeyFingerprintIsTruncatedSHA256(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	sum := sha256.Sum256(key)
	want := "3eb1bd439947eb76"
	if got := HMACKeyFingerprintForKey(key); got != want || got != hexPrefix(sum[:], HMACKeyFingerprintLength) {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}
}

func TestHMACKeyDesignatedRequirementsUseTeamID(t *testing.T) {
	restoreTeamID := setHMACTeamIDForTest("TEAM123")
	defer restoreTeamID()
	got, err := HMACKeyDesignatedRequirements()
	if err != nil {
		t.Fatalf("designated requirements: %v", err)
	}
	if len(got) != 2 || !strings.Contains(got[0], `identifier "com.gethasp.hasp.HASP"`) || !strings.Contains(got[1], `identifier "com.gethasp.hasp.daemon"`) {
		t.Fatalf("requirements = %#v, want app+daemon", got)
	}
	for _, requirement := range got {
		if !strings.Contains(requirement, `certificate leaf[subject.OU] = "TEAM123"`) ||
			!strings.Contains(requirement, `certificate 1[field.1.2.840.113635.100.6.2.6] exists`) {
			t.Fatalf("requirement missing Team ID or Developer ID clause: %s", requirement)
		}
	}
}

func TestHMACKeyDesignatedRequirementsRequiresTeamIDOutsideTests(t *testing.T) {
	restoreTeamID := setHMACTeamIDForTest("")
	defer restoreTeamID()
	restore := osArgs0ForTest(t, "/usr/local/bin/hasp")
	defer restore()
	if _, err := HMACKeyDesignatedRequirements(); err == nil {
		t.Fatal("expected missing team id error")
	}
}

func TestHMACKeyAdditionalEdgeBranches(t *testing.T) {
	oldCurrentUsername := currentUsername
	currentUsername = func() string { return "" }
	if _, err := HMACKeyAccount(); err == nil {
		t.Fatal("blank current username should fail account lookup")
	}
	currentUsername = oldCurrentUsername

	if _, err := designatedRequirement("", "TEAM"); err == nil {
		t.Fatal("blank bundle id should fail designated requirement")
	}
	if got, err := designatedRequirement("com.example.App", "TEAM123456"); err != nil || got != `identifier "com.example.App"` {
		t.Fatalf("debug designated requirement = %q err=%v", got, err)
	}
	if _, err := decodeHMACKey("not-base64"); err == nil {
		t.Fatal("malformed HMAC key should fail decoding")
	}
	if isMissingKeyringItem(nil) || !isMissingKeyringItem(errors.New("No Such item")) || !isRecoverableMissingHMACKey(store.KeyringItemNotFoundError{Err: errors.New("missing")}) {
		t.Fatal("missing keyring item detection failed")
	}
	if isRecoverableMissingHMACKey(store.ErrKeyringUnavailable) {
		t.Fatal("keyring unavailable must not be recoverable")
	}

	if goruntime.GOOS == "darwin" {
		restoreTeamID := setHMACTeamIDForTest("TEAM123456")
		defer restoreTeamID()
		home := t.TempDir()
		t.Setenv("HASP_HOME", home)
		path := filepath.Join(home, localDebugHMACKeyFile)
		if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
			t.Fatalf("write short debug key: %v", err)
		}
		key, err := loadOrCreateLocalDebugHMACKey()
		if err != nil {
			t.Fatalf("load or recreate invalid debug key: %v", err)
		}
		if len(key) != sha256.Size {
			t.Fatalf("recreated debug key length = %d", len(key))
		}
		if loaded, err := loadLocalDebugHMACKey(); err != nil || string(loaded) != string(key) {
			t.Fatalf("loaded debug key = %x err=%v", loaded, err)
		}
		if reinit, err := ReinitializeHMACKey(context.TODO(), &memoryHMACKeyring{}); err != nil || len(reinit) != sha256.Size {
			t.Fatalf("reinitialize local debug key len=%d err=%v", len(reinit), err)
		}
		restoreTeamID()
		restoreTeamIDAgain := setHMACTeamIDForTest("TEAM123456")
		defer restoreTeamIDAgain()
		blockingHome := filepath.Join(t.TempDir(), "file-home")
		if err := os.WriteFile(blockingHome, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("write blocking home: %v", err)
		}
		t.Setenv("HASP_HOME", blockingHome)
		if _, err := createLocalDebugHMACKey(); err == nil {
			t.Fatal("local debug key creation should fail when HASP_HOME is a file")
		}
	}
}

func TestHMACKeyResidualErrorBranches(t *testing.T) {
	oldCurrentUsername := currentUsername
	t.Cleanup(func() { currentUsername = oldCurrentUsername })
	currentUsername = func() string { return "" }
	if _, err := LoadOrCreateHMACKey(context.Background(), &memoryHMACKeyring{}); err == nil {
		t.Fatal("load or create HMAC key should fail without account")
	}
	if _, err := LoadHMACKey(&memoryHMACKeyring{}); err == nil {
		t.Fatal("load HMAC key should fail without account")
	}
	if _, err := ReinitializeHMACKey(context.TODO(), &memoryHMACKeyring{}); err == nil {
		t.Fatal("reinitialize HMAC key should fail without account")
	}
	currentUsername = oldCurrentUsername

	if _, err := LoadProvisionedHMACKey(&memoryHMACKeyring{getErr: store.ErrKeyringUnavailable}); !errors.Is(err, store.ErrKeyringUnavailable) {
		t.Fatalf("non-missing provisioned error = %v", err)
	}
	if _, err := HMACKeyFingerprint(context.Background(), &memoryHMACKeyring{getErr: store.ErrKeyringUnavailable}); !errors.Is(err, store.ErrKeyringUnavailable) {
		t.Fatalf("fingerprint load error = %v", err)
	}
	calls := 0
	currentUsername = func() string {
		calls++
		if calls == 1 {
			return "tester"
		}
		return ""
	}
	if _, err := LoadOrCreateHMACKey(context.Background(), &memoryHMACKeyring{}); err == nil || !strings.Contains(err.Error(), "current user") {
		t.Fatalf("second account lookup error = %v", err)
	}
	currentUsername = func() string { return "tester" }
	if _, err := ReinitializeHMACKey(context.Background(), &memoryHMACKeyring{setErr: store.ErrKeyringUnavailable}); !errors.Is(err, store.ErrKeyringUnavailable) {
		t.Fatalf("reinitialize write error = %v", err)
	}
	if got, err := localDebugHMACKeyPath(); err != nil || got == "" {
		t.Fatalf("local debug key path = %q err=%v", got, err)
	}
}

func TestHMACKeyOSAndRandomFailureBranches(t *testing.T) {
	oldCurrentUserFn := currentUserFn
	oldHMACRandomFn := hmacRandomFn
	oldUserHomeDirFn := userHomeDirFn
	oldHMACRuntimeOS := hmacRuntimeOS
	oldCurrentUsername := currentUsername
	t.Cleanup(func() {
		currentUserFn = oldCurrentUserFn
		hmacRandomFn = oldHMACRandomFn
		userHomeDirFn = oldUserHomeDirFn
		hmacRuntimeOS = oldHMACRuntimeOS
		currentUsername = oldCurrentUsername
	})

	currentUserFn = func() (*user.User, error) {
		return nil, errors.New("user lookup failed")
	}
	t.Setenv("USER", "fallback-user")
	if account, err := HMACKeyAccount(); err != nil || account != "fallback-user" {
		t.Fatalf("fallback account = %q err=%v", account, err)
	}
	t.Setenv("USER", "")
	if _, err := HMACKeyAccount(); err == nil {
		t.Fatal("missing OS and env user should fail")
	}

	currentUsername = func() string { return "tester" }
	hmacRandomFn = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	if _, err := LoadOrCreateHMACKey(context.Background(), &memoryHMACKeyring{}); err == nil || !strings.Contains(err.Error(), "generate HTTP HMAC key") {
		t.Fatalf("create random failure = %v", err)
	}
	if _, err := ReinitializeHMACKey(context.Background(), &memoryHMACKeyring{}); err == nil || !strings.Contains(err.Error(), "generate HTTP HMAC key") {
		t.Fatalf("reinitialize random failure = %v", err)
	}

	hmacRuntimeOS = "darwin"
	restoreTeamID := setHMACTeamIDForTest("TEAM123456")
	defer restoreTeamID()
	t.Setenv("HASP_HOME", "")
	userHomeDirFn = func() (string, error) { return "", errors.New("home unavailable") }
	if _, err := localDebugHMACKeyPath(); err == nil {
		t.Fatal("missing user home should fail local debug key path")
	}
}

func TestHMACKeyLocalDebugSeamsCoverResidualBranches(t *testing.T) {
	oldRuntimeOS := hmacRuntimeOS
	oldReadFile := hmacReadFile
	oldMkdirAll := hmacMkdirAll
	oldWriteFile := hmacWriteFile
	oldRandomFn := hmacRandomFn
	oldHomeDirFn := userHomeDirFn
	t.Cleanup(func() {
		hmacRuntimeOS = oldRuntimeOS
		hmacReadFile = oldReadFile
		hmacMkdirAll = oldMkdirAll
		hmacWriteFile = oldWriteFile
		hmacRandomFn = oldRandomFn
		userHomeDirFn = oldHomeDirFn
	})

	hmacRuntimeOS = "darwin"
	restoreTeamID := setHMACTeamIDForTest("TEAM123456")
	defer restoreTeamID()
	home := t.TempDir()
	t.Setenv("HASP_HOME", home)

	key, err := LoadOrCreateHMACKey(context.TODO(), nil)
	if err != nil {
		t.Fatalf("load or create local debug key with defaults: %v", err)
	}
	if len(key) != sha256.Size {
		t.Fatalf("local debug key length = %d", len(key))
	}
	if loaded, err := LoadHMACKey(nil); err != nil || string(loaded) != string(key) {
		t.Fatalf("load local debug key = %x err=%v", loaded, err)
	}
	if fingerprint, err := HMACKeyFingerprint(context.Background(), nil); err != nil || len(fingerprint) != HMACKeyFingerprintLength {
		t.Fatalf("fingerprint local debug key = %q err=%v", fingerprint, err)
	}
	if loadedAgain, err := LoadOrCreateHMACKey(context.Background(), nil); err != nil || string(loadedAgain) != string(key) {
		t.Fatalf("load existing local debug key = %x err=%v", loadedAgain, err)
	}

	hmacReadFile = func(string) ([]byte, error) { return nil, errors.New("permission denied") }
	if _, err := LoadHMACKey(nil); err == nil || !strings.Contains(err.Error(), "read HTTP HMAC key") {
		t.Fatalf("local debug load failure = %v", err)
	}
	if _, err := loadOrCreateLocalDebugHMACKey(); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("unexpected non-recoverable local debug load error: %v", err)
	}

	hmacReadFile = oldReadFile
	t.Setenv("HASP_HOME", "")
	userHomeDirFn = func() (string, error) { return "", errors.New("home unavailable") }
	if _, err := LoadHMACKey(nil); err == nil || !strings.Contains(err.Error(), "user home") {
		t.Fatalf("local debug path load error = %v", err)
	}
	if _, err := ReinitializeHMACKey(context.TODO(), nil); err == nil || !strings.Contains(err.Error(), "user home") {
		t.Fatalf("local debug path create error = %v", err)
	}
	userHomeDirFn = func() (string, error) { return home, nil }
	t.Setenv("HASP_HOME", home)

	hmacRandomFn = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	if _, err := createLocalDebugHMACKey(); err == nil || !strings.Contains(err.Error(), "generate HTTP HMAC key") {
		t.Fatalf("local debug random failure = %v", err)
	}
	hmacRandomFn = oldRandomFn

	hmacMkdirAll = func(string, os.FileMode) error { return errors.New("mkdir denied") }
	if _, err := createLocalDebugHMACKey(); err == nil || !strings.Contains(err.Error(), "mkdir denied") {
		t.Fatalf("local debug mkdir failure = %v", err)
	}
	hmacMkdirAll = oldMkdirAll

	hmacWriteFile = func(string, []byte, os.FileMode) error { return errors.New("write denied") }
	if _, err := createLocalDebugHMACKey(); err == nil || !strings.Contains(err.Error(), "write denied") {
		t.Fatalf("local debug write failure = %v", err)
	}
	hmacWriteFile = oldWriteFile

	t.Setenv("HASP_HOME", "")
	userHomeDirFn = func() (string, error) { return home, nil }
	if got, err := localDebugHMACKeyPath(); err != nil || !strings.Contains(got, "Application Support") {
		t.Fatalf("default local debug path = %q err=%v", got, err)
	}

	restoreTeamID()
	restoreTeamIDAgain := setHMACTeamIDForTest("")
	defer restoreTeamIDAgain()
	requirements, err := HMACKeyDesignatedRequirements()
	if err != nil {
		t.Fatalf("test fallback team id should build requirements: %v", err)
	}
	if len(requirements) != 2 || !strings.Contains(requirements[0], "TEAMID1234") {
		t.Fatalf("fallback requirements = %#v", requirements)
	}

	restoreArgs0 := osArgs0ForTest(t, "/usr/local/bin/hasp")
	if err := storeHMACKey(context.Background(), &protectedMemoryHMACKeyring{}, "tester", base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))); err == nil || !strings.Contains(err.Error(), "HMACTeamID") {
		t.Fatalf("protected store missing team id error = %v", err)
	}
	restoreArgs0()
}

func setHMACTeamIDForTest(value string) func() {
	old := HMACTeamID
	HMACTeamID = value
	return func() { HMACTeamID = old }
}

func osArgs0ForTest(t *testing.T, value string) func() {
	t.Helper()
	old := os.Args[0]
	os.Args[0] = value
	return func() { os.Args[0] = old }
}

func hexPrefix(sum []byte, n int) string {
	const digits = "0123456789abcdef"
	out := make([]byte, n)
	for i := 0; i < n; i += 2 {
		b := sum[i/2]
		out[i] = digits[b>>4]
		out[i+1] = digits[b&0x0f]
	}
	return string(out)
}
