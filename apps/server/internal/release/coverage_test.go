package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read") }

type fakeWriteCloser struct {
	writeErr error
	closeErr error
	short    bool
}

func (f fakeWriteCloser) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short && len(p) > 0 {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func (f fakeWriteCloser) Close() error { return f.closeErr }

func TestCoveragePlatformAndHTTPGet(t *testing.T) {
	origGOOS := releaseGOOS
	releaseGOOS = "windows"
	if got := PlatformBinaryName(); got != "hasp.exe" {
		t.Fatalf("windows binary = %q", got)
	}
	releaseGOOS = origGOOS

	if _, err := DefaultHTTPGet(context.Background(), "://bad", 10); err == nil {
		t.Fatal("expected parse error")
	}

	origTransport := http.DefaultClient.Transport
	t.Cleanup(func() { http.DefaultClient.Transport = origTransport })
	http.DefaultClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("User-Agent") != "hasp-upgrade" {
			t.Fatalf("missing user agent")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	body, err := DefaultHTTPGet(context.Background(), "https://github.com/gethasp/hasp/releases/download/v1/file", 10)
	if err != nil || string(body) != "ok" {
		t.Fatalf("http success body=%q err=%v", body, err)
	}
	http.DefaultClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network")
	})
	if _, err := DefaultHTTPGet(context.Background(), "https://github.com/gethasp/hasp/releases/download/v1/file", 10); err == nil {
		t.Fatal("expected network error")
	}
	http.DefaultClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTeapot, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if _, err := DefaultHTTPGet(context.Background(), "https://github.com/gethasp/hasp/releases/download/v1/file", 10); err == nil {
		t.Fatal("expected status error")
	}
	http.DefaultClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(errReader{})}, nil
	})
	if _, err := DefaultHTTPGet(context.Background(), "https://github.com/gethasp/hasp/releases/download/v1/file", 10); err == nil {
		t.Fatal("expected read error")
	}
	http.DefaultClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("too-large"))}, nil
	})
	if _, err := DefaultHTTPGet(context.Background(), "https://github.com/gethasp/hasp/releases/download/v1/file", 3); err == nil {
		t.Fatal("expected cap error")
	}

	origNewRequest := newReleaseRequest
	t.Cleanup(func() { newReleaseRequest = origNewRequest })
	newReleaseRequest = func(context.Context, string, string, io.Reader) (*http.Request, error) {
		return nil, errors.New("request")
	}
	if _, err := DefaultHTTPGet(context.Background(), "https://github.com/gethasp/hasp/releases/download/v1/file", 10); err == nil {
		t.Fatal("expected request error")
	}
}

func TestCoverageExtractBinaryErrorsAndSeams(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "hasp")
	if err := ExtractBinary([]byte("not gzip"), "hasp", dst); err == nil {
		t.Fatal("expected gzip error")
	}
	var broken bytes.Buffer
	gz := gzip.NewWriter(&broken)
	if _, err := gz.Write([]byte("not tar")); err != nil {
		t.Fatalf("write broken gzip: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close broken gzip: %v", err)
	}
	if err := ExtractBinary(broken.Bytes(), "hasp", dst); err == nil {
		t.Fatal("expected tar read error")
	}
	if err := ExtractBinary(makeTarballWithTypes(t, []tarEntry{{name: "hasp", typeflag: '5'}}), "hasp", dst); !errors.Is(err, ErrUnsafeTarball) {
		t.Fatalf("expected type error, got %v", err)
	}
	if err := ExtractBinary(makeTarballWithTypes(t, []tarEntry{{name: "hasp", body: nil, size: 0, typeflag: '0'}}), "hasp", dst); !errors.Is(err, ErrUnsafeTarball) {
		t.Fatalf("expected size error, got %v", err)
	}

	origOpen := openInstallFile
	origRemove := removeInstallFile
	origChmod := chmodInstallFile
	t.Cleanup(func() {
		openInstallFile = origOpen
		removeInstallFile = origRemove
		chmodInstallFile = origChmod
	})
	openInstallFile = func(string, int, os.FileMode) (writeCloser, error) { return nil, errors.New("open") }
	if err := ExtractBinary(makeTarball(t, map[string][]byte{"hasp": []byte("body")}), "hasp", dst); err == nil {
		t.Fatal("expected open error")
	}
	openInstallFile = func(string, int, os.FileMode) (writeCloser, error) {
		return fakeWriteCloser{writeErr: errors.New("write")}, nil
	}
	if err := ExtractBinary(makeTarball(t, map[string][]byte{"hasp": []byte("body")}), "hasp", dst); err == nil {
		t.Fatal("expected write error")
	}
	openInstallFile = func(string, int, os.FileMode) (writeCloser, error) {
		return fakeWriteCloser{closeErr: errors.New("close")}, nil
	}
	if err := ExtractBinary(makeTarball(t, map[string][]byte{"hasp": []byte("body")}), "hasp", dst); err == nil {
		t.Fatal("expected close error")
	}
	openInstallFile = origOpen
	chmodInstallFile = func(string, os.FileMode) error { return errors.New("chmod") }
	if err := ExtractBinary(makeTarball(t, map[string][]byte{"hasp": []byte("body")}), "hasp", dst); err == nil {
		t.Fatal("expected chmod error")
	}
	readRandOrig := readRand
	readRand = func([]byte) (int, error) { return 0, errors.New("rand") }
	if _, err := StagingPath("/tmp/hasp"); err == nil {
		t.Fatal("expected random error")
	}
	readRand = readRandOrig
}

type tarEntry struct {
	name     string
	body     []byte
	size     int64
	typeflag byte
}

func makeTarballWithTypes(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		size := entry.size
		if size == 0 && entry.body != nil {
			size = int64(len(entry.body))
		}
		if entry.typeflag == 0 {
			entry.typeflag = '0'
		}
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o755, Size: size, Typeflag: entry.typeflag}); err != nil {
			t.Fatalf("header: %v", err)
		}
		if len(entry.body) > 0 {
			if _, err := tw.Write(entry.body); err != nil {
				t.Fatalf("body: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestCoverageKeysVerifyVersionsAndProgress(t *testing.T) {
	restore := SetPinnedKeysForTest(" ,nothex," + strings.Repeat("00", ed25519.PublicKeySize) + "," + strings.Repeat("01", ed25519.PublicKeySize-1))
	defer restore()
	if keys := PinnedPublicKeys(); len(keys) != 1 {
		t.Fatalf("expected one valid pinned key, got %d", len(keys))
	}
	if _, err := parseKEYS([]byte(strings.Repeat("aa", ed25519.PublicKeySize+1) + "\n")); err == nil {
		t.Fatal("expected malformed key length")
	}
	if _, err := parseKEYS(bytes.Repeat([]byte("a"), 70*1024)); err == nil {
		t.Fatal("expected scanner error")
	}
	if _, err := VerifyTarball([]byte("body"), []byte("short"), [][]byte{[]byte("bad")}); err == nil {
		t.Fatal("expected short signature error")
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, err := VerifyTarball([]byte("body"), make([]byte, ed25519.SignatureSize), [][]byte{pub}); !errors.Is(err, ErrUntrustedTarball) {
		t.Fatalf("expected untrusted tarball, got %v", err)
	}
	if !verifyAny([][]byte{pub}, []byte("body"), make([]byte, ed25519.SignatureSize)) {
		// expected false path covered
	} else {
		t.Fatal("bad key verified")
	}
	if verifyAny([][]byte{[]byte("bad")}, []byte("body"), make([]byte, ed25519.SignatureSize)) {
		t.Fatal("short key verified")
	}
	if got := (SemVer{Major: 1, Minor: 2, Patch: 2}).Compare(SemVer{Major: 1, Minor: 2, Patch: 3}); got != -1 {
		t.Fatalf("patch compare = %d", got)
	}
	if got := (SemVer{Major: 1, Minor: 2, Patch: 4}).Compare(SemVer{Major: 1, Minor: 2, Patch: 3}); got != 1 {
		t.Fatalf("patch compare high = %d", got)
	}
	if got := (SemVer{Major: 1, Minor: 2, Patch: 3, Prerelease: "z"}).Compare(SemVer{Major: 1, Minor: 2, Patch: 3, Prerelease: "a"}); got != 1 {
		t.Fatalf("prerelease default compare = %d", got)
	}
	progress(nil, "ignored")
}

func TestCoverageUpgradeDefaultsAndFailures(t *testing.T) {
	opts, _, pinPub, _ := fixture(t, "0.1.0", "0.2.0")
	restore := SetPinnedKeysForTest(hex.EncodeToString(pinPub))
	defer restore()
	opts.Pinned = nil
	if _, err := Upgrade(context.Background(), opts); err != nil {
		t.Fatalf("expected default pinned keys to work: %v", err)
	}

	opts, fh, _, _ := fixture(t, "0.1.0", "0.2.0")
	opts.HTTPGet = nil
	if _, err := Upgrade(context.Background(), opts); err == nil {
		t.Fatal("expected default HTTP getter to reject fake host")
	}

	opts, fh, _, _ = fixture(t, "0.1.0", "0.2.0")
	opts.URLBase = ""
	opts.GOOS = ""
	opts.GOARCH = ""
	if _, err := Upgrade(context.Background(), opts); err == nil {
		t.Fatal("expected fake downloader to reject default artifact URL")
	}
	_ = fh

	opts, _, _, _ = fixture(t, "0.1.0", "0.2.0")
	opts.HTTPGet = func(context.Context, string, int64) ([]byte, error) { return nil, errors.New("download") }
	if _, err := Upgrade(context.Background(), opts); err == nil {
		t.Fatal("expected keys download error")
	}
	opts, fh, _, _ = fixture(t, "0.1.0", "0.2.0")
	calls := 0
	opts.HTTPGet = func(ctx context.Context, url string, max int64) ([]byte, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("keys sig")
		}
		return fh.get(ctx, url, max)
	}
	if _, err := Upgrade(context.Background(), opts); err == nil {
		t.Fatal("expected keys signature download error")
	}
	opts, fh, _, _ = fixture(t, "0.1.0", "0.2.0")
	calls = 0
	opts.HTTPGet = func(ctx context.Context, url string, max int64) ([]byte, error) {
		calls++
		if calls == 3 {
			return nil, errors.New("tar")
		}
		return fh.get(ctx, url, max)
	}
	if _, err := Upgrade(context.Background(), opts); err == nil {
		t.Fatal("expected tarball download error")
	}
	opts, fh, _, _ = fixture(t, "0.1.0", "0.2.0")
	calls = 0
	opts.HTTPGet = func(ctx context.Context, url string, max int64) ([]byte, error) {
		calls++
		if calls == 4 {
			return nil, errors.New("tar sig")
		}
		return fh.get(ctx, url, max)
	}
	if _, err := Upgrade(context.Background(), opts); err == nil {
		t.Fatal("expected tar signature download error")
	}

	opts, _, _, _ = fixture(t, "0.1.0", "0.2.0")
	origReadRand := readRand
	t.Cleanup(func() { readRand = origReadRand })
	readRand = func([]byte) (int, error) { return 0, errors.New("rand") }
	if _, err := Upgrade(context.Background(), opts); err == nil {
		t.Fatal("expected staging path error")
	}
	readRand = origReadRand

	opts, _, _, _ = fixture(t, "0.1.0", "0.2.0")
	opts.TargetPath = t.TempDir()
	if _, err := Upgrade(context.Background(), opts); err == nil {
		t.Fatal("expected atomic replace error")
	}

	opts, fh, _, _ = fixture(t, "0.1.0", "0.2.0")
	opts.HTTPGet = fh.get
	opts.TargetPath = filepath.Join(t.TempDir(), "missing", "hasp")
	if _, err := Upgrade(context.Background(), opts); err == nil {
		t.Fatal("expected extract/replace failure")
	}
}
