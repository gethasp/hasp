//go:build !darwin

package store

func NewDefaultKeyring() Keyring {
	return unsupportedKeyring{}
}
