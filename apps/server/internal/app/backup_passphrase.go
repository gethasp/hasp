package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// passphraseMaxBytes is the upper bound for passphrase reads to prevent
// OOM from malformed input.
const passphraseMaxBytes = 4096

// stdinReaderFn is a seam that returns the reader for --recovery-passphrase-stdin.
// Tests substitute a strings.Reader to avoid touching os.Stdin.
var stdinReaderFn func() io.Reader = func() io.Reader { return os.Stdin }

// openFDFn is a seam that wraps os.NewFile. Tests substitute a pipe so no
// real file descriptor mapping is needed.
var openFDFn func(fd uintptr) *os.File = func(fd uintptr) *os.File {
	return os.NewFile(fd, "passphrase-fd")
}

// errArgvPassphrase is returned when the caller supplies a passphrase via argv.
// The error message deliberately names every safer alternative.
var errArgvPassphrase = errors.New(
	"passphrase via argv is not allowed; use --recovery-passphrase-stdin, --recovery-passphrase-fd N, or HASP_BACKUP_PASSPHRASE",
)

// errArgvMasterPassword is returned when the caller supplies a master password via argv.
var errArgvMasterPassword = errors.New(
	"master-password via argv is not allowed; use --recovery-passphrase-stdin, --recovery-passphrase-fd N, or HASP_MASTER_PASSWORD",
)

// readPassphrase resolves a passphrase from exactly one of three safe sources:
//   - stdinFlag == true: read until EOF or first newline from stdinReaderFn()
//   - fdFlag >= 0: read from that file descriptor via openFDFn
//   - envFallback != "": use it directly
//
// envName is the name of the env var checked by the caller; it appears in
// missing-source and ambiguity errors so users know which variable to set
// or unset (hasp-su09).
//
// An empty passphrase after trimming is rejected. The function trims a
// trailing \r\n or \n from the read result.
func readPassphrase(stdinFlag bool, fdFlag int, envFallback string, envName string) (string, error) {
	if envName == "" {
		envName = "HASP_BACKUP_PASSPHRASE"
	}
	sources := 0
	if stdinFlag {
		sources++
	}
	if fdFlag >= 0 {
		sources++
	}
	if envFallback != "" {
		sources++
	}

	switch {
	case sources == 0:
		return "", fmt.Errorf("passphrase is required; use --recovery-passphrase-stdin, --recovery-passphrase-fd N, or set %s", envName)
	case sources > 1:
		return "", fmt.Errorf("specify exactly one passphrase source (--recovery-passphrase-stdin, --recovery-passphrase-fd, or %s)", envName)
	}

	var raw string
	switch {
	case stdinFlag:
		lr := io.LimitReader(stdinReaderFn(), passphraseMaxBytes)
		data, err := io.ReadAll(lr)
		if err != nil {
			return "", fmt.Errorf("read passphrase from stdin: %w", err)
		}
		raw = string(data)
	case fdFlag >= 0:
		f := openFDFn(uintptr(fdFlag))
		if f == nil {
			return "", fmt.Errorf("could not open fd %d for passphrase", fdFlag)
		}
		lr := io.LimitReader(f, passphraseMaxBytes)
		data, err := io.ReadAll(lr)
		f.Close()
		if err != nil {
			return "", fmt.Errorf("read passphrase from fd %d: %w", fdFlag, err)
		}
		raw = string(data)
	default:
		raw = envFallback
	}

	// Trim trailing CRLF / LF only (not interior whitespace).
	pp := strings.TrimRight(raw, "\r\n")
	if pp == "" {
		return "", errors.New("passphrase must not be empty")
	}
	return pp, nil
}
