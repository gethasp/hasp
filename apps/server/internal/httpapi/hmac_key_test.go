package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
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
