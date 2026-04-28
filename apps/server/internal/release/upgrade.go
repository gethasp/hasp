package release

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
)

// UpgradeOptions configures a single upgrade attempt.
type UpgradeOptions struct {
	// CurrentVersion is the version of the running binary, formatted
	// as "X.Y.Z" or "vX.Y.Z" (the leading v is optional).
	CurrentVersion string

	// TargetVersion is the version to install. Required — there is
	// no auto-discovery seam in v1; callers must pick the version.
	TargetVersion string

	// TargetPath is the absolute path to the running binary; the
	// upgrade replaces this file in place. AtomicReplace requires
	// staging on the same directory, so the user must have write
	// access to that directory (typically root for /usr/local/bin).
	TargetPath string

	// URLBase defaults to DefaultReleaseURLBase when empty.
	URLBase string

	// GOOS / GOARCH default to runtime.GOOS / runtime.GOARCH.
	GOOS   string
	GOARCH string

	// HTTPGet defaults to DefaultHTTPGet. Tests inject a fake.
	HTTPGet HTTPGetFunc

	// Pinned defaults to PinnedPublicKeys(). Tests inject explicit
	// keys via SetPinnedKeysForTest.
	Pinned [][]byte

	// Progress receives human-readable progress lines (one per
	// completed step). nil silences progress output.
	Progress io.Writer
}

// UpgradeReport is returned on a successful Upgrade for downstream
// audit logging or human-readable rendering.
type UpgradeReport struct {
	FromVersion string
	ToVersion   string
	SignerKey   string
	StagedAt    string
	InstalledAt string
}

// Upgrade performs the full signed upgrade flow: downgrade refusal,
// download, signature verification (KEYS chain + tarball), atomic
// install. Any failure short-circuits BEFORE the on-disk binary is
// touched.
func Upgrade(ctx context.Context, opts UpgradeOptions) (UpgradeReport, error) {
	if opts.TargetPath == "" {
		return UpgradeReport{}, errors.New("upgrade: TargetPath is required")
	}
	if opts.TargetVersion == "" {
		return UpgradeReport{}, errors.New("upgrade: TargetVersion is required")
	}
	if opts.URLBase == "" {
		opts.URLBase = DefaultReleaseURLBase
	}
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.GOARCH == "" {
		opts.GOARCH = runtime.GOARCH
	}
	if opts.HTTPGet == nil {
		opts.HTTPGet = DefaultHTTPGet
	}
	pinned := opts.Pinned
	if pinned == nil {
		pinned = PinnedPublicKeys()
	}
	if len(pinned) == 0 {
		return UpgradeReport{}, ErrNoPinnedKeys
	}

	if err := CheckUpgrade(opts.CurrentVersion, opts.TargetVersion); err != nil {
		return UpgradeReport{}, err
	}
	progress(opts.Progress, "Verified target %s is newer than installed %s", opts.TargetVersion, opts.CurrentVersion)

	tarballURL, tarballSigURL, keysURL, keysSigURL := ArtifactURLs(opts.URLBase, opts.TargetVersion, opts.GOOS, opts.GOARCH)

	keysFile, err := opts.HTTPGet(ctx, keysURL, MaxSmallArtifactBytes)
	if err != nil {
		return UpgradeReport{}, fmt.Errorf("download KEYS: %w", err)
	}
	keysSig, err := opts.HTTPGet(ctx, keysSigURL, MaxSmallArtifactBytes)
	if err != nil {
		return UpgradeReport{}, fmt.Errorf("download KEYS signature: %w", err)
	}
	trustedKeys, err := VerifyKEYS(keysFile, keysSig, pinned)
	if err != nil {
		return UpgradeReport{}, fmt.Errorf("verify KEYS: %w", err)
	}
	progress(opts.Progress, "Verified KEYS file with embedded trust root (%d active keys)", len(trustedKeys))

	tarball, err := opts.HTTPGet(ctx, tarballURL, MaxTarballBytes)
	if err != nil {
		return UpgradeReport{}, fmt.Errorf("download tarball: %w", err)
	}
	tarballSig, err := opts.HTTPGet(ctx, tarballSigURL, MaxSmallArtifactBytes)
	if err != nil {
		return UpgradeReport{}, fmt.Errorf("download tarball signature: %w", err)
	}
	signerFP, err := VerifyTarball(tarball, tarballSig, trustedKeys)
	if err != nil {
		return UpgradeReport{}, fmt.Errorf("verify tarball: %w", err)
	}
	progress(opts.Progress, "Verified tarball signed by %s...", signerFP[:16])

	staged, err := StagingPath(opts.TargetPath)
	if err != nil {
		return UpgradeReport{}, err
	}
	if err := ExtractBinary(tarball, PlatformBinaryName(), staged); err != nil {
		return UpgradeReport{}, fmt.Errorf("extract: %w", err)
	}
	progress(opts.Progress, "Extracted %s to %s", PlatformBinaryName(), staged)

	if err := AtomicReplace(staged, opts.TargetPath); err != nil {
		return UpgradeReport{}, fmt.Errorf("atomic replace: %w", err)
	}
	progress(opts.Progress, "Replaced %s atomically", opts.TargetPath)

	return UpgradeReport{
		FromVersion: opts.CurrentVersion,
		ToVersion:   opts.TargetVersion,
		SignerKey:   signerFP,
		StagedAt:    staged,
		InstalledAt: opts.TargetPath,
	}, nil
}

func progress(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format+"\n", args...)
}
