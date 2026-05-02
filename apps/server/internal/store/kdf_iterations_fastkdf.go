//go:build hasp_test_fastkdf

package store

// defaultPasswordIterations under the hasp_test_fastkdf build tag uses a much
// lower cost so the test suite stays fast. The tag must be passed explicitly
// to `go test` and is never set in release builds.
const defaultPasswordIterations = testPasswordIterations
