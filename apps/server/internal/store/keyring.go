package store

import (
	"context"
	"errors"
)

type Keyring interface {
	Set(ctx context.Context, service string, account string, value string) error
	Get(service string, account string) (string, error)
	Delete(service string, account string) error
}

type DesignatedRequirementKeyring interface {
	Keyring
	SetWithDesignatedRequirements(ctx context.Context, service string, account string, value string, requirements []string) error
}

type NativeKeyring interface {
	Keyring
	GetNative(service string, account string) (string, error)
	DeleteNative(service string, account string) error
}

type unsupportedKeyring struct{}

type KeyringItemNotFoundError struct {
	Err error
}

func (e KeyringItemNotFoundError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return "keyring item not found"
}

func (e KeyringItemNotFoundError) Unwrap() error {
	return e.Err
}

func IsKeyringItemNotFound(err error) bool {
	var notFound KeyringItemNotFoundError
	return errors.As(err, &notFound)
}

func (unsupportedKeyring) Set(context.Context, string, string, string) error {
	return ErrKeyringUnavailable
}

func (unsupportedKeyring) Get(string, string) (string, error) {
	return "", ErrKeyringUnavailable
}

func (unsupportedKeyring) Delete(string, string) error {
	return ErrKeyringUnavailable
}
