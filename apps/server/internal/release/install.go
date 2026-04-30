package release

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ErrTarballEmpty is returned when the tarball contains no entries
// matching the expected binary name.
var ErrTarballEmpty = errors.New("tarball does not contain the expected binary")

// ErrUnsafeTarball is returned when a tarball entry escapes the
// extraction directory (path traversal) or has an unexpected type.
var ErrUnsafeTarball = errors.New("tarball contains an unsafe entry")

// MaxBinarySize bounds extraction so a malicious tarball cannot
// fill disk before signature verification (verification happens
// before this code runs, but we still cap as defence in depth).
const MaxBinarySize int64 = 256 * 1024 * 1024

type writeCloser interface {
	io.Writer
	Close() error
}

var (
	openInstallFile = func(name string, flag int, perm os.FileMode) (writeCloser, error) {
		return os.OpenFile(name, flag, perm)
	}
	removeInstallFile = os.Remove
	chmodInstallFile  = os.Chmod
)

// ExtractBinary reads tarballGzip, finds an entry whose base name
// equals binaryName, and writes its content to dst with mode 0755.
// dst must be on the same filesystem as the eventual install target
// for AtomicReplace to work.
func ExtractBinary(tarballGzip []byte, binaryName, dst string) error {
	gz, err := gzip.NewReader(strings.NewReader(string(tarballGzip)))
	if err != nil {
		return fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		if filepath.Base(hdr.Name) != binaryName {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("%w: %q is not a regular file", ErrUnsafeTarball, hdr.Name)
		}
		if hdr.Size <= 0 || hdr.Size > MaxBinarySize {
			return fmt.Errorf("%w: %q size %d out of bounds", ErrUnsafeTarball, hdr.Name, hdr.Size)
		}
		// Path traversal: the embedded name might be "../../etc/sudo".
		// We don't honour the embedded path at all — we write to dst.
		// But we still refuse outright if the name looks malicious so
		// the failure mode is loud rather than silently overwriting dst.
		if strings.Contains(hdr.Name, "..") {
			return fmt.Errorf("%w: %q contains parent traversal", ErrUnsafeTarball, hdr.Name)
		}
		f, err := openInstallFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return fmt.Errorf("create %s: %w", dst, err)
		}
		_, err = io.CopyN(f, tr, hdr.Size)
		closeErr := f.Close()
		if err != nil {
			_ = removeInstallFile(dst)
			return fmt.Errorf("extract %s: %w", dst, err)
		}
		if closeErr != nil {
			_ = removeInstallFile(dst)
			return fmt.Errorf("close %s: %w", dst, closeErr)
		}
		// Belt-and-braces chmod: O_CREATE honoured umask.
		if err := chmodInstallFile(dst, 0o755); err != nil {
			_ = removeInstallFile(dst)
			return fmt.Errorf("chmod %s: %w", dst, err)
		}
		return nil
	}
	return fmt.Errorf("%w: %q", ErrTarballEmpty, binaryName)
}

// AtomicReplace renames stagedPath onto targetPath. Both must be on
// the same filesystem; on POSIX, rename(2) is atomic — readers see
// either the old inode or the new one, never a half-written file.
//
// On macOS/Linux the running process keeps executing the OLD inode
// until it exits, so the swap is safe even if the upgrade runs from
// the very binary being replaced.
func AtomicReplace(stagedPath, targetPath string) error {
	if filepath.Dir(stagedPath) != filepath.Dir(targetPath) {
		return fmt.Errorf("staged and target must share a directory; got %q vs %q",
			filepath.Dir(stagedPath), filepath.Dir(targetPath))
	}
	return os.Rename(stagedPath, targetPath)
}

// StagingPath returns "<targetPath>.upgrade-<8-hex>" — a sibling of
// the target on the same filesystem.
func StagingPath(targetPath string) (string, error) {
	var rand8 [4]byte
	if _, err := readRand(rand8[:]); err != nil {
		return "", fmt.Errorf("random suffix: %w", err)
	}
	return targetPath + ".upgrade-" + hex.EncodeToString(rand8[:]), nil
}

var readRand = rand.Read
