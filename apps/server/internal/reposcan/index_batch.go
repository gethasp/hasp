package reposcan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/gitsafe"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

type indexObject struct{ path, oid, mode, status string }

var indexGitCommand = gitsafe.BuildIndexCommand

// Raw NUL-delimited diff records capture paths and immutable object IDs in one
// index read. No path is sent through cat-file's line-delimited input protocol.
func readIndexObjects(ctx context.Context, root string) ([]indexObject, error) {
	cmd := indexGitCommand(ctx, root, "diff", "--cached", "--raw", "--no-abbrev", "--no-renames", "--no-ext-diff", "--no-textconv", "--ignore-submodules=none", "--diff-filter=ACMRTU", "-z")
	out, err := cmd.Output()
	var entries []indexObject
	parts := bytes.Split(out, []byte{0})
	for len(parts) > 1 {
		if len(parts) < 3 {
			return entries, errors.New("incomplete Git index record")
		}
		fields := strings.Fields(string(parts[0]))
		if len(fields) != 5 || !strings.HasPrefix(fields[0], ":") || !validObjectID(fields[3]) || len(parts[1]) == 0 {
			return entries, errors.New("invalid Git index record")
		}
		entries = append(entries, indexObject{path: string(parts[1]), oid: fields[3], mode: fields[1], status: fields[4]})
		parts = parts[2:]
	}
	if len(parts) != 1 || len(parts[0]) != 0 {
		return entries, errors.New("unterminated Git index record")
	}
	return entries, err
}

func scanStagedObjects(ctx context.Context, root string, items []store.Item, maxBytes int64, index func([]byte, []byte) int) (result Result, resultErr error) {
	defer result.finish(time.Now())
	result.Walker, result.Complete = "git-staged", true
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	start := time.Now()
	entries, enumErr := readIndexObjects(ctx, root)
	result.Stats.EnumerationMS = elapsedMS(start)
	result.Stats.SourcesEnumerated = len(entries)
	var failures []error
	if enumErr != nil {
		result.addIssue(".", "enumeration_failed", enumErr)
		failures = append(failures, enumErr)
	}
	compiled := result.compile(items)
	if len(entries) == 0 {
		return result, errors.Join(failures...)
	}
	start = time.Now()
	batch, err := startObjectBatch(ctx, root)
	result.Stats.ReadMS += elapsedMS(start)
	if err != nil {
		result.addIssue(".", "index_read_failed", err)
		return result, errors.Join(append(failures, err)...)
	}
	defer func() {
		if err := batch.close(resultErr != nil); err != nil && resultErr == nil {
			result.addIssue(".", "index_read_failed", err)
			resultErr = err
		}
	}()
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			result.addIssue(entry.path, "cancelled", err)
			failures = append(failures, err)
			break
		}
		if entry.status == "U" || zeroObjectID(entry.oid) || entry.mode == "160000" {
			err := fmt.Errorf("index entry %q has no scannable stage-0 blob", entry.path)
			result.addIssue(entry.path, "index_read_failed", err)
			failures = append(failures, err)
			continue
		}
		start = time.Now()
		kind, size, exists, err := batch.info(entry.oid)
		result.Stats.ReadMS += elapsedMS(start)
		if err == nil && (!exists || kind != "blob") {
			err = errors.New("index blob is unavailable")
		}
		if err != nil {
			result.addIssue(entry.path, "index_read_failed", err)
			failures = append(failures, err)
			continue
		}
		if size > maxBytes {
			result.Complete = false
			result.Skipped = append(result.Skipped, Skipped{Path: entry.path, Size: size, Reason: "over_max_bytes"})
			continue
		}
		data, err := measure(&result.Stats.ReadMS, func() ([]byte, error) { return batch.contents(entry.oid, kind, size) })
		if err != nil {
			result.addIssue(entry.path, "index_read_failed", err)
			failures = append(failures, err)
			// A truncated protocol response cannot safely frame later objects.
			break
		}
		result.match(entry.path, data, compiled, index)
	}
	return result, errors.Join(failures...)
}
