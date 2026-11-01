//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package store

func lockEnvelopeReplacement(string) (func(), error) { return func() {}, nil }
