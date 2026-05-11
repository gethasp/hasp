package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

const (
	HMACKeyService           = "com.gethasp.hasp.daemon.http"
	localDebugHMACKeyFile    = "daemon.http.hmac.debug"
	HMACKeyFingerprintLength = 16
	HASPDaemonBundleID       = "com.gethasp.hasp.daemon"
)

// HMACTeamID is injected at build time for signed macOS app/daemon builds.
// Runtime environment variables must not participate in the keychain ACL trust
// root; an unset value fails closed outside Go tests.
var HMACTeamID = ""

var ErrHMACSecretNotProvisioned = errors.New("HMAC secret not provisioned")

var currentUsername = func() string {
	if current, err := user.Current(); err == nil {
		return strings.TrimSpace(current.Username)
	}
	if isGoTestProcess() {
		if envUser := strings.TrimSpace(os.Getenv("USER")); envUser != "" {
			return envUser
		}
	}
	return ""
}

func HMACKeyAccount() (string, error) {
	account := currentUsername()
	if account == "" {
		return "", errors.New("httpapi: current user is required for HMAC key account")
	}
	return account, nil
}

func LoadOrCreateHMACKey(ctx context.Context, keyring store.Keyring) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if keyring == nil {
		keyring = store.NewDefaultKeyring()
	}
	if usesLocalDebugHMACKey() {
		return loadOrCreateLocalDebugHMACKey()
	}
	key, err := LoadHMACKey(keyring)
	if err == nil {
		return key, nil
	}
	if !isRecoverableMissingHMACKey(err) {
		return nil, err
	}
	account, accountErr := HMACKeyAccount()
	if accountErr != nil {
		return nil, accountErr
	}
	key = make([]byte, sha256.Size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate HTTP HMAC key: %w", err)
	}
	if err := storeHMACKey(ctx, keyring, account, base64.StdEncoding.EncodeToString(key)); err != nil {
		return nil, fmt.Errorf("write HTTP HMAC key: %w", err)
	}
	return key, nil
}

func storeHMACKey(ctx context.Context, keyring store.Keyring, account string, encodedKey string) error {
	if protected, ok := keyring.(store.DesignatedRequirementKeyring); ok {
		requirements, err := HMACKeyDesignatedRequirements()
		if err != nil {
			return err
		}
		return protected.SetWithDesignatedRequirements(ctx, HMACKeyService, account, encodedKey, requirements)
	}
	if isGoTestProcess() || !requiresProtectedHMACKeyring() {
		return keyring.Set(ctx, HMACKeyService, account, encodedKey)
	}
	return fmt.Errorf("%w: HTTP HMAC key requires designated-requirement keyring", store.ErrKeyringUnavailable)
}

func HMACKeyDesignatedRequirements() ([]string, error) {
	teamID := strings.TrimSpace(HMACTeamID)
	if teamID == "" {
		if isGoTestProcess() {
			teamID = "TEAMID1234"
		} else {
			return nil, errors.New("httpapi: build-time HMACTeamID is required for HTTP HMAC key ACL")
		}
	}
	appRequirement, err := designatedRequirement(HASPAppBundleID, teamID)
	if err != nil {
		return nil, err
	}
	daemonRequirement, err := designatedRequirement(HASPDaemonBundleID, teamID)
	if err != nil {
		return nil, err
	}
	return []string{appRequirement, daemonRequirement}, nil
}

func designatedRequirement(bundleID string, teamID string) (string, error) {
	bundleID = strings.TrimSpace(bundleID)
	teamID = strings.TrimSpace(teamID)
	if bundleID == "" || teamID == "" {
		return "", errors.New("httpapi: bundle id and team id are required for designated requirement")
	}
	if teamID == "TEAM123456" {
		return fmt.Sprintf(`identifier "%s"`, bundleID), nil
	}
	return fmt.Sprintf(`identifier "%s" and anchor apple generic and certificate leaf[subject.OU] = "%s" and certificate 1[field.1.2.840.113635.100.6.2.6] exists`, bundleID, teamID), nil
}

func LoadHMACKey(keyring store.Keyring) ([]byte, error) {
	if keyring == nil {
		keyring = store.NewDefaultKeyring()
	}
	if usesLocalDebugHMACKey() {
		key, err := loadLocalDebugHMACKey()
		if err != nil {
			return nil, fmt.Errorf("read HTTP HMAC key: %w", err)
		}
		return key, nil
	}
	account, err := HMACKeyAccount()
	if err != nil {
		return nil, err
	}
	encoded, err := getHMACKey(keyring, account)
	if err == nil {
		return decodeHMACKey(encoded)
	}
	return nil, fmt.Errorf("read HTTP HMAC key: %w", err)
}

func LoadProvisionedHMACKey(keyring store.Keyring) ([]byte, error) {
	key, err := LoadHMACKey(keyring)
	if err == nil {
		return key, nil
	}
	if store.IsKeyringItemNotFound(err) || isMissingKeyringItem(err) {
		return nil, fmt.Errorf("%w: %v", ErrHMACSecretNotProvisioned, err)
	}
	return nil, err
}

func ReinitializeHMACKey(ctx context.Context, keyring store.Keyring) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if keyring == nil {
		keyring = store.NewDefaultKeyring()
	}
	if usesLocalDebugHMACKey() {
		return createLocalDebugHMACKey()
	}
	account, err := HMACKeyAccount()
	if err != nil {
		return nil, err
	}
	key := make([]byte, sha256.Size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate HTTP HMAC key: %w", err)
	}
	if err := storeHMACKey(ctx, keyring, account, base64.StdEncoding.EncodeToString(key)); err != nil {
		return nil, fmt.Errorf("write HTTP HMAC key: %w", err)
	}
	return key, nil
}

func HMACKeyFingerprint(_ context.Context, keyring store.Keyring) (string, error) {
	key, err := LoadHMACKey(keyring)
	if err != nil {
		return "", err
	}
	return HMACKeyFingerprintForKey(key), nil
}

func HMACKeyFingerprintForKey(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])[:HMACKeyFingerprintLength]
}

func decodeHMACKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decode HTTP HMAC key: %w", err)
	}
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("decode HTTP HMAC key: got %d bytes, want %d", len(key), sha256.Size)
	}
	return key, nil
}

func isMissingKeyringItem(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "could not be found") ||
		strings.Contains(msg, "item not found") ||
		strings.Contains(msg, "no such")
}

func isRecoverableMissingHMACKey(err error) bool {
	if store.IsKeyringItemNotFound(err) {
		return true
	}
	if errors.Is(err, store.ErrKeyringUnavailable) {
		return false
	}
	return isMissingKeyringItem(err)
}

func isGoTestProcess() bool {
	return strings.HasSuffix(os.Args[0], ".test")
}

func usesLocalDebugHMACKey() bool {
	return runtime.GOOS == "darwin" && strings.TrimSpace(HMACTeamID) == "TEAM123456"
}

func loadOrCreateLocalDebugHMACKey() ([]byte, error) {
	key, err := loadLocalDebugHMACKey()
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !strings.Contains(strings.ToLower(err.Error()), "invalid") {
		return nil, err
	}
	return createLocalDebugHMACKey()
}

func loadLocalDebugHMACKey() ([]byte, error) {
	path, err := localDebugHMACKeyPath()
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("invalid local debug HTTP HMAC key length %d", len(key))
	}
	return key, nil
}

func createLocalDebugHMACKey() ([]byte, error) {
	path, err := localDebugHMACKeyPath()
	if err != nil {
		return nil, err
	}
	key := make([]byte, sha256.Size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate HTTP HMAC key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func localDebugHMACKeyPath() (string, error) {
	if home := strings.TrimSpace(os.Getenv("HASP_HOME")); home != "" {
		return filepath.Join(home, localDebugHMACKeyFile), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", errors.New("httpapi: user home is required for local debug HMAC key")
	}
	return filepath.Join(home, "Library", "Application Support", "hasp", localDebugHMACKeyFile), nil
}

func getHMACKey(keyring store.Keyring, account string) (string, error) {
	if native, ok := keyring.(store.NativeKeyring); ok {
		return native.GetNative(HMACKeyService, account)
	}
	return keyring.Get(HMACKeyService, account)
}
