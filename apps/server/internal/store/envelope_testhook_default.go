//go:build !hasp_test_fastkdf

package store

// ConfigureEnvelopeDurabilityForTests is a no-op outside the fast test build.
func ConfigureEnvelopeDurabilityForTests() func() {
	return func() {}
}
