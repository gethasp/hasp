package reposcan

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestOversizedSourcesAreScannedInAllModes(t *testing.T) {
	root := newOutgoingRepo(t, "sha1")
	base := outgoingCommit(t, root, "base", "clean", "base")
	secret := "synthetic-stream-boundary-credential"
	items := []store.Item{{Name: "token", Value: []byte(secret)}}
	// Cross both a read boundary and a former cap; repeat to check deduplication.
	data := strings.Repeat("x", (64<<10)-7) + secret + strings.Repeat("y", 128<<10) + secret
	file := filepath.Join(root, "large.bin")
	if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, got Result, err error) {
		t.Helper()
		if err != nil || !got.Complete || len(got.Skipped) != 0 || len(got.Matches) != 1 || got.Stats.BytesScanned < int64(len(data)) {
			t.Fatalf("oversized source: %+v, %v", got, err)
		}
	}
	t.Run("working", func(t *testing.T) {
		got, err := Scan(context.Background(), root, items, 64, Deps{})
		check(t, got, err)
	})
	outgoingGit(t, root, "add", "large.bin")
	t.Run("index", func(t *testing.T) {
		got, err := ScanStaged(context.Background(), root, items, 64, Deps{})
		check(t, got, err)
	})
	outgoingGit(t, root, "commit", "-m", "large")
	tip := outgoingGit(t, root, "rev-parse", "HEAD")
	t.Run("outgoing", func(t *testing.T) {
		got, err := ScanOutgoing(context.Background(), root, items, 64, []RefUpdate{{"HEAD", tip, "refs/heads/main", base}}, "")
		check(t, got, err)
	})
	if err := os.WriteFile(file, []byte(strings.Repeat("z", 256<<10)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("clean", func(t *testing.T) {
		got, err := Scan(context.Background(), root, items, 64, Deps{})
		if err != nil || !got.Complete || len(got.Skipped) != 0 || len(got.Matches) != 0 {
			t.Fatalf("clean oversized source: %+v, %v", got, err)
		}
	})
}

type repeatingReader struct{}

func (repeatingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestStreamingMemoryDoesNotGrowWithSource(t *testing.T) {
	compiled := compileItems(outgoingTestItems)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var result Result
	err := result.matchReader(context.Background(), "large", io.LimitReader(repeatingReader{}, 128<<20), compiled)
	runtime.ReadMemStats(&after)
	if err != nil || result.Stats.BytesScanned != 128<<20 || result.Stats.SourcesScanned != 1 {
		t.Fatalf("stream stats: %+v, %v", result.Stats, err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2<<20 {
		t.Fatalf("128 MiB stream allocated %d bytes", allocated)
	}
}

func TestStreamingPreservesLongPatternsAndRejectsReadFailures(t *testing.T) {
	pattern := strings.Repeat("long-secret-", 7000)
	compiled := []compiledItem{{name: "long", needles: [][]byte{[]byte(pattern)}}}
	var result Result
	err := result.matchReader(context.Background(), "long", strings.NewReader(strings.Repeat("x", 65530)+pattern), compiled)
	if err != nil || len(result.Matches) != 1 {
		t.Fatalf("long pattern missed: %+v, %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := result.matchReader(ctx, "cancelled", repeatingReader{}, compiled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled stream: %v", err)
	}
	if err := result.matchReader(context.Background(), "failed", errorReader{}, compiled); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("failed stream: %v", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, os.ErrPermission }

func TestStreamingGitRejectsTruncatedAndUnframedObjects(t *testing.T) {
	oid := strings.Repeat("a", 40)
	for _, response := range []string{oid + " blob 3\nx", oid + " blob 3\nxxx", oid + " blob 3\nxxxx", oid + " tree 3\nxxx\n"} {
		batch := &objectBatch{input: discardProtocolInput{io.Discard}, output: bufio.NewReader(strings.NewReader(response))}
		var result Result
		if err := batch.scanContents(oid, "blob", 3, func(reader io.Reader) error {
			return result.matchReader(context.Background(), "object", reader, nil)
		}); err == nil {
			t.Fatalf("invalid stream passed: %q", response)
		}
	}
}
