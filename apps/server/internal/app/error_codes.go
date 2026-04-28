package app

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
// nil → 0, plain errors → 1 (generic), unknown codes → 1.
func appErrorExitCode(err error) int {
	if err == nil {
		return exitOK
	}
	envelope, ok := err.(*appError)
	if !ok {
		return exitGeneric
	}
	if bucket, known := errCodeExitBuckets[envelope.Code]; known {
		return bucket
	}
	return exitGeneric
}
