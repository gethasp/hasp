package store

import (
	"errors"
	"fmt"
)

// MinPasswordLength is the floor enforced by EnforcePasswordPolicy. The
// number is small enough that a memorable passphrase ("correct horse
// battery staple", "hunter2hunter2") clears it in one breath, yet large
// enough to make trivial-password mistakes ("abc", "letmein") fail
// closed at vault creation rather than at the next breach.
const MinPasswordLength = 12

// EnforcePasswordPolicy is hasp's UX-layer guard against pinning a brand
// new vault to a trivially-weak master password. It runs only on the
// vault-creation path (bootstrap / setup) and is intentionally separate
// from validateMasterPassword, which still applies to every Open*
// callsite — Open paths must accept whatever the user already chose.
//
// Policy:
//
//   - Length floor of MinPasswordLength runes after trimming. Passphrases
//     beat complexity rules in practice (NIST SP 800-63B) so we measure
//     length, not character classes.
//   - Reject single-character runs (e.g. "aaaaaaaaaaaa") because they
//     contribute zero entropy regardless of length.
//
// The CLI surfaces a `--skip-password-policy` flag that bypasses this
// function for operators with their own policy (corporate password
// manager, FIDO-derived secret, etc.).
func EnforcePasswordPolicy(password string) error {
	if len([]rune(password)) < MinPasswordLength {
		return fmt.Errorf("master password must be at least %d characters; pass --skip-password-policy to override", MinPasswordLength)
	}
	if uniformPassword(password) {
		return errors.New("master password must contain more than one distinct character; pass --skip-password-policy to override")
	}
	return nil
}

func uniformPassword(password string) bool {
	if password == "" {
		return false
	}
	first := password[0]
	for i := 1; i < len(password); i++ {
		if password[i] != first {
			return false
		}
	}
	return true
}
