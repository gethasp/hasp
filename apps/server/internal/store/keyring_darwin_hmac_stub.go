//go:build darwin && (!cgo || hasp_test_fastkdf)

package store

import (
	"context"
	"fmt"
)

func (DarwinKeyring) SetWithDesignatedRequirements(context.Context, string, string, string, []string) error {
	return fmt.Errorf("%w: designated-requirement keychain ACLs require cgo", ErrKeyringUnavailable)
}

func (DarwinKeyring) GetNative(string, string) (string, error) {
	return "", fmt.Errorf("%w: native keychain reads require cgo", ErrKeyringUnavailable)
}

func (DarwinKeyring) DeleteNative(string, string) error {
	return fmt.Errorf("%w: native keychain deletes require cgo", ErrKeyringUnavailable)
}
