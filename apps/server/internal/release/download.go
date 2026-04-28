package release

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
)

// DefaultReleaseHost is the canonical host for hasp release artifacts.
// Downloads from any other host are refused — a MitM that redirects
// the URL has to either land on github.com (where signatures still
// have to verify) or fail the host pin.
const DefaultReleaseHost = "github.com"

// DefaultReleaseURLBase is the URL prefix for downloaded artifacts.
// Every artifact for version vX.Y.Z lives at:
//
//	{base}/v{X.Y.Z}/{filename}
const DefaultReleaseURLBase = "https://github.com/gethasp/hasp/releases/download"

// MaxArtifactBytes caps each download. The tarball cap is generous;
// signature and KEYS files are tiny and will hit MaxSmallArtifactBytes.
const (
	MaxTarballBytes      int64 = 256 * 1024 * 1024
	MaxSmallArtifactBytes int64 = 64 * 1024
)

// ErrUntrustedHost is returned when an artifact URL points outside
// the pinned release host.
var ErrUntrustedHost = errors.New("artifact URL is not on the pinned release host")

// Artifact names follow a stable scheme. Tools/release/sign.go and
// the publishing pipeline must produce these exact names.
//
//	hasp-v0.2.0-darwin-arm64.tar.gz
//	hasp-v0.2.0-darwin-arm64.tar.gz.sig
//	KEYS-v0.2.0
//	KEYS-v0.2.0.sig
func TarballName(version, goos, goarch string) string {
	return fmt.Sprintf("hasp-v%s-%s-%s.tar.gz", strings.TrimPrefix(version, "v"), goos, goarch)
}

func KEYSName(version string) string {
	return "KEYS-v" + strings.TrimPrefix(version, "v")
}

// PlatformBinaryName is the name of the binary inside the tarball.
// On Windows it would be "hasp.exe", but Windows is unsupported in
// v1 (rename-over-running-binary doesn't work without extra work).
func PlatformBinaryName() string {
	if runtime.GOOS == "windows" {
		return "hasp.exe"
	}
	return "hasp"
}

// HTTPGetFunc abstracts the HTTP call so tests can supply fake
// payloads without standing up a real server.
type HTTPGetFunc func(ctx context.Context, url string, maxBytes int64) ([]byte, error)

// DefaultHTTPGet is the production downloader. It enforces:
//   - URL host matches DefaultReleaseHost (host pin)
//   - Status 200
//   - Body size ≤ maxBytes (defence in depth; signatures still verify)
//   - HTTPS only (Go's net/http does not auto-upgrade plain http://;
//     callers should pass https URLs only).
func DefaultHTTPGet(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: %q must be https", ErrUntrustedHost, rawURL)
	}
	if parsed.Host != DefaultReleaseHost {
		return nil, fmt.Errorf("%w: %q is on %q, expected %q", ErrUntrustedHost, rawURL, parsed.Host, DefaultReleaseHost)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "hasp-upgrade")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http get %s: status %d", rawURL, resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("artifact exceeds %d byte cap", maxBytes)
	}
	return body, nil
}

// ArtifactURLs returns the four URLs needed to upgrade to version
// (which must include a leading "v" or not — both are accepted).
func ArtifactURLs(base, version, goos, goarch string) (tarball, tarballSig, keys, keysSig string) {
	tag := "v" + strings.TrimPrefix(version, "v")
	tarballName := TarballName(version, goos, goarch)
	keysName := KEYSName(version)
	prefix := strings.TrimSuffix(base, "/") + "/" + tag + "/"
	return prefix + tarballName,
		prefix + tarballName + ".sig",
		prefix + keysName,
		prefix + keysName + ".sig"
}
