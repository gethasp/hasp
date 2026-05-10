//go:build darwin

package httpapi

func requiresProtectedHMACKeyring() bool {
	return true
}
