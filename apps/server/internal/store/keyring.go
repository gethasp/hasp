package store

import "context"

type Keyring interface {
	Set(ctx context.Context, service string, account string, value string) error
	Get(service string, account string) (string, error)
	Delete(service string, account string) error
}

type unsupportedKeyring struct{}

func (unsupportedKeyring) Set(context.Context, string, string, string) error {
	return ErrKeyringUnavailable
}

func (unsupportedKeyring) Get(string, string) (string, error) {
	return "", ErrKeyringUnavailable
}

func (unsupportedKeyring) Delete(string, string) error {
	return ErrKeyringUnavailable
}
