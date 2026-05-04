package store

import "testing"

// TestExportedKDFAndFormatMetadata covers the public accessors that
// `hasp version --json` reads to surface format/KDF defaults.
func TestExportedKDFAndFormatMetadata(t *testing.T) {
	if got := FormatVersion(); got != formatVersion {
		t.Fatalf("FormatVersion = %d, want %d", got, formatVersion)
	}
	if got := DefaultKDFName(); got != "argon2id" {
		t.Fatalf("DefaultKDFName = %q, want argon2id", got)
	}
	if got := DefaultKDFIterations(); got != passwordIterations || got <= 0 {
		t.Fatalf("DefaultKDFIterations = %d, want %d (and positive)", got, passwordIterations)
	}
	if DefaultKDFTime() == 0 || DefaultKDFMemoryKiB() == 0 || DefaultKDFParallelism() == 0 {
		t.Fatalf("argon2id defaults must be non-zero: time=%d memory=%d parallelism=%d", DefaultKDFTime(), DefaultKDFMemoryKiB(), DefaultKDFParallelism())
	}
}
