package reposcan

import (
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// Stats contains counts and elapsed times only; no values or command input.
// Sources are files for working/index scans and Git objects for outgoing scans.
type Stats struct {
	SourcesEnumerated  int     `json:"sources_enumerated"`
	SourcesScanned     int     `json:"sources_scanned"`
	BytesScanned       int64   `json:"bytes_scanned"`
	Items              int     `json:"items"`
	ConfigurationItems int     `json:"configuration_items"`
	Patterns           int     `json:"patterns"`
	Skipped            int     `json:"skipped"`
	Issues             int     `json:"issues"`
	Deleted            int     `json:"deleted"`
	EnumerationMS      float64 `json:"enumeration_ms"`
	CompileMS          float64 `json:"compile_ms"`
	ReadMS             float64 `json:"read_ms"`
	MatchMS            float64 `json:"match_ms"`
	TotalMS            float64 `json:"total_ms"`
	VaultMS            float64 `json:"vault_ms,omitempty"`
	CommandMS          float64 `json:"command_ms,omitempty"`
}

func elapsedMS(start time.Time) float64 {
	return float64(time.Since(start)) / float64(time.Millisecond)
}

func (r *Result) finish(start time.Time) {
	r.Stats.TotalMS = elapsedMS(start)
	r.Stats.Skipped = len(r.Skipped)
	r.Stats.Issues = len(r.Issues)
	r.Stats.Deleted = len(r.Deleted)
}

func (r *Result) compile(items []store.Item) []compiledItem {
	start := time.Now()
	compiled := compileItems(items)
	for _, item := range items {
		if !item.Confidential() {
			r.Stats.ConfigurationItems++
		}
	}
	r.Stats.CompileMS = elapsedMS(start)
	r.Stats.Items = len(compiled)
	for _, item := range compiled {
		r.Stats.Patterns += len(item.needles)
	}
	return compiled
}

func (r *Result) match(path string, data []byte, compiled []compiledItem, index ...func([]byte, []byte) int) {
	start := time.Now()
	r.Stats.SourcesScanned++
	r.Stats.BytesScanned += int64(len(data))
	for _, item := range compiled {
		if hitNeedles(data, item.needles, index...) {
			r.Matches = append(r.Matches, Match{Path: path, ItemName: item.name})
		}
	}
	r.Stats.MatchMS += elapsedMS(start)
}

func measure[T any](total *float64, read func() (T, error)) (T, error) {
	start := time.Now()
	value, err := read()
	*total += elapsedMS(start)
	return value, err
}
