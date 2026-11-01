package reposcan

import (
	"context"
	"errors"
	"io"
	"time"
)

// matchReader retains one chunk and enough overlap for the longest encoded
// secret. Memory depends on the pattern set, never on the source length.
func (r *Result) matchReader(ctx context.Context, path string, source io.Reader, compiled []compiledItem, index ...func([]byte, []byte) int) error {
	const chunkSize = 64 << 10
	overlap := 0
	for _, item := range compiled {
		for _, needle := range item.needles {
			if len(needle)-1 > overlap {
				overlap = len(needle) - 1
			}
		}
	}
	buffer := make([]byte, chunkSize+overlap)
	found := make([]bool, len(compiled))
	retained := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := measure(&r.Stats.ReadMS, func() (int, error) {
			return io.ReadFull(source, buffer[retained:retained+chunkSize])
		})
		r.Stats.BytesScanned += int64(n)
		data := buffer[:retained+n]
		start := time.Now()
		for i, item := range compiled {
			if !found[i] && hitNeedles(data, item.needles, index...) {
				found[i] = true
				r.Matches = append(r.Matches, Match{Path: path, ItemName: item.name})
			}
		}
		r.Stats.MatchMS += elapsedMS(start)
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
				r.Stats.SourcesScanned++
				return nil
			}
			return readErr
		}
		retained = min(overlap, len(data))
		copy(buffer, data[len(data)-retained:])
	}
}

func (b *objectBatch) scanContents(oid, kind string, size int64, scan func(io.Reader) error) error {
	actualKind, actualSize, exists, err := b.header("contents", oid)
	if err != nil {
		return err
	}
	if !exists || kind != actualKind || size != actualSize {
		return errors.New("object changed during Git scan")
	}
	source := &io.LimitedReader{R: b.output, N: size}
	if err := scan(source); err != nil {
		return err
	}
	if source.N != 0 {
		return io.ErrUnexpectedEOF
	}
	if end, err := b.output.ReadByte(); err != nil || end != '\n' {
		return errors.New("incomplete Git object contents")
	}
	return nil
}
