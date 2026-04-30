package app

import (
	"errors"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// hasp-a7xd: stable error-code registry. Codes are surfaced in the
// structured-error envelope (--json mode) and mapped to documented exit-code
// buckets so scripts can branch on machine-readable failure.
//
// Buckets:
//
//	0  ok
//	1  generic / internal
//	2  user input (missing flag, malformed grammar, not in a repo)
//	3  permission (vault locked, wrong password, grant denied)
//	4  daemon / I/O (daemon unreachable, broker timeout)
//	5  leak detected (repo scan turned up managed values)
//	6  not found (named secret/binding/grant not in vault) — hasp-sc13
const (
	errCodeInternal          = "E_INTERNAL"
	errCodeUserInput         = "E_USER_INPUT"
	errCodeNotInRepo         = "E_NOT_IN_REPO"
	errCodePermission        = "E_PERMISSION"
	errCodeGrantDenied       = "E_GRANT_DENIED"
	errCodeVaultLocked       = "E_VAULT_LOCKED"
	errCodePasswordWrong     = "E_PASSWORD_WRONG"
	errCodeDaemonUnreachable = "E_DAEMON_UNREACHABLE"
	errCodeRepoLeak          = "E_REPO_LEAK"
	errCodeNotFound          = "E_NOT_FOUND"
)

const (
	exitOK           = 0
	exitGeneric      = 1
	exitUserInput    = 2
	exitPermission   = 3
	exitDaemonOrIO   = 4
	exitLeakDetected = 5
	exitNotFound     = 6
)

var errCodeExitBuckets = map[string]int{
	errCodeInternal:          exitGeneric,
	errCodeUserInput:         exitUserInput,
	errCodeNotInRepo:         exitUserInput,
	errCodePermission:        exitPermission,
	errCodeGrantDenied:       exitPermission,
	errCodeVaultLocked:       exitPermission,
	errCodePasswordWrong:     exitPermission,
	errCodeDaemonUnreachable: exitDaemonOrIO,
	errCodeRepoLeak:          exitLeakDetected,
	errCodeNotFound:          exitNotFound,
}

// AppErrorExitCode is the binary-boundary entry point for appErrorExitCode.
func AppErrorExitCode(err error) int {
	return appErrorExitCode(err)
}

// appErrorExitCode returns the documented exit-code bucket for err.
// nil -> 0, classified plain errors -> their bucket, unknown codes -> 1.
func appErrorExitCode(err error) int {
	if err == nil {
		return exitOK
	}
	envelope := classifyAppError(err)
	if bucket, known := errCodeExitBuckets[envelope.Code]; known {
		return bucket
	}
	return exitGeneric
}

func classifyAppError(err error) *appError {
	if err == nil {
		return nil
	}
	var envelope *appError
	if errors.As(err, &envelope) {
		return envelope
	}
	message := err.Error()
	switch {
	case errors.Is(err, store.ErrVaultNotInitialized):
		return newAppError(errCodeVaultLocked, message).withHint("run hasp setup or set HASP_MASTER_PASSWORD")
	case errors.Is(err, store.ErrInvalidPassword):
		return newAppError(errCodePasswordWrong, message)
	case errors.Is(err, store.ErrItemNotFound):
		return newAppError(errCodeNotFound, message)
	case looksLikeUserInputError(message):
		return newAppError(errCodeUserInput, message)
	case looksLikeDaemonError(message):
		return newAppError(errCodeDaemonUnreachable, message)
	default:
		return newAppError(errCodeInternal, message)
	}
}

func looksLikeUserInputError(message string) bool {
	lower := strings.ToLower(message)
	return strings.HasPrefix(lower, "unknown command") ||
		strings.HasPrefix(lower, "usage:") ||
		strings.Contains(lower, "flag provided but not defined") ||
		strings.Contains(lower, "invalid value") ||
		strings.Contains(lower, "requires ") ||
		strings.Contains(lower, "missing ") ||
		strings.Contains(lower, "not in a git repository") ||
		strings.Contains(lower, "refusing to overwrite")
}

func looksLikeDaemonError(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "daemon") &&
		(strings.Contains(lower, "not reachable") ||
			strings.Contains(lower, "unreachable") ||
			strings.Contains(lower, "connection refused") ||
			strings.Contains(lower, "dial unix"))
}
