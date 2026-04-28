package release

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeHTTP struct {
	files map[string][]byte
	calls []string
	err   error
}

func (f *fakeHTTP) get(_ context.Context, url string, _ int64) ([]byte, error) {
	f.calls = append(f.calls, url)
	if f.err != nil {
		return nil, f.err
	}
	body, ok := f.files[url]
	if !ok {
		return nil, fmt.Errorf("404: %s", url)
	}
	return body, nil
}

// fixture wires together a signed release in-memory: KEYS file, sigs,
// and a tarball containing a fake "hasp" binary. Returns a configured
// UpgradeOptions ready to drive Upgrade through fakeHTTP.
func fixture(t *testing.T, currentVersion, targetVersion string) (UpgradeOptions, *fakeHTTP, ed25519.PublicKey, []byte) {
	t.Helper()
	pinPub, pinPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen pin: %v", err)
	}
	releasePub, releasePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen release: %v", err)
	}

	keysFile := []byte("# trusted set\n" + hex.EncodeToString(releasePub) + " release-key\n")
	keysSig := ed25519.Sign(pinPriv, keysFile)

	tarball := makeTarball(t, map[string][]byte{
		"hasp": []byte("\x7fELF-fake-binary-v" + targetVersion),
	})
	tarballSig := ed25519.Sign(releasePriv, tarball)

	tarballURL, tarballSigURL, keysURL, keysSigURL := ArtifactURLs("https://example.test/dl", targetVersion, "darwin", "arm64")
	fh := &fakeHTTP{files: map[string][]byte{
		keysURL:       keysFile,
		keysSigURL:    keysSig,
		tarballURL:    tarball,
		tarballSigURL: tarballSig,
	}}

	dir := t.TempDir()
	target := filepath.Join(dir, "hasp")
	if err := os.WriteFile(target, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	opts := UpgradeOptions{
		CurrentVersion: currentVersion,
		TargetVersion:  targetVersion,
		TargetPath:     target,
		URLBase:        "https://example.test/dl",
		GOOS:           "darwin",
		GOARCH:         "arm64",
		HTTPGet:        fh.get,
		Pinned:         [][]byte{pinPub},
		Progress:       io.Discard,
	}
	return opts, fh, pinPub, tarball
}

func TestUpgradeHappyPath(t *testing.T) {
	opts, _, _, _ := fixture(t, "0.1.32", "0.2.0")
	report, err := Upgrade(context.Background(), opts)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if report.ToVersion != "0.2.0" {
		t.Errorf("ToVersion = %q", report.ToVersion)
	}
	got, _ := os.ReadFile(opts.TargetPath)
	if !strings.Contains(string(got), "fake-binary-v0.2.0") {
		t.Errorf("target binary not replaced: %q", got)
	}
	// staging path should be cleaned up by the atomic rename.
	if _, err := os.Stat(report.StagedAt); !os.IsNotExist(err) {
		t.Errorf("expected staging to be gone, err=%v", err)
	}
}

func TestUpgradeRefusesDowngrade(t *testing.T) {
	opts, _, _, _ := fixture(t, "0.2.0", "0.1.32")
	_, err := Upgrade(context.Background(), opts)
	if !errors.Is(err, ErrDowngrade) {
		t.Fatalf("expected ErrDowngrade, got %v", err)
	}
}

func TestUpgradeRefusesUntrustedKEYS(t *testing.T) {
	opts, _, _, _ := fixture(t, "0.1.32", "0.2.0")
	// Replace pinned set with a key the fixture didn't sign with.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	opts.Pinned = [][]byte{otherPub}
	_, err := Upgrade(context.Background(), opts)
	if !errors.Is(err, ErrUntrustedKEYS) {
		t.Fatalf("expected ErrUntrustedKEYS, got %v", err)
	}
	// Critical: target binary must not be touched.
	got, _ := os.ReadFile(opts.TargetPath)
	if string(got) != "old-binary" {
		t.Errorf("target was modified despite verification failure: %q", got)
	}
}

func TestUpgradeRefusesTamperedTarball(t *testing.T) {
	opts, fh, _, _ := fixture(t, "0.1.32", "0.2.0")
	tarballURL, _, _, _ := ArtifactURLs(opts.URLBase, opts.TargetVersion, opts.GOOS, opts.GOARCH)
	bad := append([]byte{}, fh.files[tarballURL]...)
	bad[0] ^= 0x01
	fh.files[tarballURL] = bad
	_, err := Upgrade(context.Background(), opts)
	if !errors.Is(err, ErrUntrustedTarball) {
		t.Fatalf("expected ErrUntrustedTarball, got %v", err)
	}
	got, _ := os.ReadFile(opts.TargetPath)
	if string(got) != "old-binary" {
		t.Errorf("target was modified despite tarball tampering: %q", got)
	}
}

func TestUpgradeFailsWithoutPinnedKeys(t *testing.T) {
	opts, _, _, _ := fixture(t, "0.1.32", "0.2.0")
	opts.Pinned = nil
	restore := SetPinnedKeysForTest("")
	defer restore()
	_, err := Upgrade(context.Background(), opts)
	if !errors.Is(err, ErrNoPinnedKeys) {
		t.Fatalf("expected ErrNoPinnedKeys, got %v", err)
	}
}

func TestUpgradeRequiresTargetPath(t *testing.T) {
	opts, _, _, _ := fixture(t, "0.1.32", "0.2.0")
	opts.TargetPath = ""
	if _, err := Upgrade(context.Background(), opts); err == nil {
		t.Fatal("expected missing TargetPath to error")
	}
}

func TestUpgradeRequiresTargetVersion(t *testing.T) {
	opts, _, _, _ := fixture(t, "0.1.32", "0.2.0")
	opts.TargetVersion = ""
	if _, err := Upgrade(context.Background(), opts); err == nil {
		t.Fatal("expected missing TargetVersion to error")
	}
}

func TestUpgradeProgressOutput(t *testing.T) {
	opts, _, _, _ := fixture(t, "0.1.32", "0.2.0")
	var buf strings.Builder
	opts.Progress = &buf
	if _, err := Upgrade(context.Background(), opts); err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Verified target 0.2.0", "Verified KEYS file", "Verified tarball signed by", "Replaced"} {
		if !strings.Contains(out, want) {
			t.Errorf("progress missing %q in:\n%s", want, out)
		}
	}
}

func TestUpgradeSurfacesDownloadError(t *testing.T) {
	opts, fh, _, _ := fixture(t, "0.1.32", "0.2.0")
	fh.err = errors.New("network down")
	_, err := Upgrade(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "network down") {
		t.Fatalf("expected network error to surface, got %v", err)
	}
}
