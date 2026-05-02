//go:build hasp_test_fastkdf

package store

import "os"

// ConfigureEnvelopeDurabilityForTests swaps durable envelope syscalls for
// deterministic equivalents in fast test binaries. Store durability tests
// still cover fsync and rename ordering directly by overriding these seams.
func ConfigureEnvelopeDurabilityForTests() func() {
	origFsyncFile := fsyncFileFn
	origFsyncDir := fsyncDirFn
	origRename := renameEnvelopeFn
	fsyncFileFn = func(*os.File) error { return nil }
	fsyncDirFn = func(string) error { return nil }
	renameEnvelopeFn = os.Rename
	return func() {
		fsyncFileFn = origFsyncFile
		fsyncDirFn = origFsyncDir
		renameEnvelopeFn = origRename
	}
}
