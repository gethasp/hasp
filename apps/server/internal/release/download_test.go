package release

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestArtifactURLsLayout(t *testing.T) {
	tarball, tarballSig, keys, keysSig := ArtifactURLs(DefaultReleaseURLBase, "0.2.0", "darwin", "arm64")
	want := []string{
		"https://github.com/gethasp/hasp/releases/download/v0.2.0/hasp-v0.2.0-darwin-arm64.tar.gz",
		"https://github.com/gethasp/hasp/releases/download/v0.2.0/hasp-v0.2.0-darwin-arm64.tar.gz.sig",
		"https://github.com/gethasp/hasp/releases/download/v0.2.0/KEYS-v0.2.0",
		"https://github.com/gethasp/hasp/releases/download/v0.2.0/KEYS-v0.2.0.sig",
	}
	got := []string{tarball, tarballSig, keys, keysSig}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("artifact %d: got %s, want %s", i, got[i], w)
		}
	}
}

func TestArtifactURLsAcceptsVPrefixedVersion(t *testing.T) {
	tarball, _, _, _ := ArtifactURLs(DefaultReleaseURLBase, "v1.2.3", "linux", "amd64")
	if !strings.Contains(tarball, "/v1.2.3/hasp-v1.2.3-linux-amd64.tar.gz") {
		t.Errorf("v-prefix not normalised: %s", tarball)
	}
}

func TestDefaultHTTPGetRefusesPlainHTTP(t *testing.T) {
	_, err := DefaultHTTPGet(context.Background(), "http://github.com/some/file", 1024)
	if !errors.Is(err, ErrUntrustedHost) {
		t.Fatalf("expected ErrUntrustedHost, got %v", err)
	}
}

func TestDefaultHTTPGetRefusesOffHost(t *testing.T) {
	_, err := DefaultHTTPGet(context.Background(), "https://evil.example/file", 1024)
	if !errors.Is(err, ErrUntrustedHost) {
		t.Fatalf("expected ErrUntrustedHost, got %v", err)
	}
}

func TestPlatformBinaryName(t *testing.T) {
	got := PlatformBinaryName()
	if got != "hasp" && got != "hasp.exe" {
		t.Fatalf("unexpected binary name: %s", got)
	}
}
