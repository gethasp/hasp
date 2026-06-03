package redactor

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// minRedactLen is the minimum byte length a secret value must have to be
// eligible for redaction. Values shorter than this are silently skipped.
const minRedactLen = 6

// Result holds the output of a redaction pass.
type Result struct {
	Output       []byte
	Redacted     bool
	Suppressed   bool     // always false in the new implementation; kept for back-compat
	MatchedItems []string // sorted, deduplicated item names that produced at least one match
}

// MinRedactLen exposes the package threshold for callers (e.g., check-repo)
// that want to apply the same "skip short secrets" policy the redactor uses.
const MinRedactLen = minRedactLen

// Needles returns every encoded-form byte slice that would be matched for
// the given value. Callers use this to scan without rewriting — e.g.
// `hasp check-repo` needs to flag files that contain any encoded form of a
// managed secret but does not want the [REDACTED] markers in its output.
// The raw value is always first; empty and sub-threshold values yield nil
// so callers can skip them uniformly.
func Needles(value []byte) [][]byte {
	if len(value) == 0 || len(value) < minRedactLen {
		return nil
	}
	needles := [][]byte{
		value,
		[]byte(base64.StdEncoding.EncodeToString(value)),
		[]byte(base64.URLEncoding.EncodeToString(value)),
		[]byte(base64.RawStdEncoding.EncodeToString(value)),
		[]byte(base64.RawURLEncoding.EncodeToString(value)),
		[]byte(hex.EncodeToString(value)),
		[]byte(strings.ToUpper(hex.EncodeToString(value))),
		[]byte(url.QueryEscape(string(value))),
		[]byte(url.PathEscape(string(value))),
		[]byte(base32.StdEncoding.EncodeToString(value)),
		[]byte(encodeHTMLEntity(value)),
		[]byte(encodeDoublePercent(value)),
		[]byte(encodeUnicodeEscape(value)),
	}
	if b, err := json.Marshal(string(value)); err == nil && len(b) >= 2 {
		needles = append(needles, b[1:len(b)-1])
	}
	// Drop any empty needles (e.g., url.QueryEscape of an already-safe value
	// can still be non-empty; guard anyway so callers never do a zero-length
	// bytes.Index which would loop).
	out := needles[:0]
	for _, n := range needles {
		if len(n) > 0 {
			out = append(out, n)
		}
	}
	return out
}

// Apply scans input for every encoding of each item's value and replaces
// matched spans with the appropriate marker. It never sets Suppressed=true
// and processes binary input as raw bytes.
func Apply(input []byte, items []store.Item) Result {
	// Sort items longest-value-first to prevent shorter secrets from
	// accidentally redacting inside a longer secret's replacement marker.
	sorted := make([]store.Item, len(items))
	copy(sorted, items)
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i].Value) > len(sorted[j].Value)
	})

	output := append([]byte(nil), input...)
	redacted := false
	matched := make(map[string]struct{})

	itemForms := make([][]formDef, len(sorted))
	totalForms := 0
	for i, it := range sorted {
		if len(it.Value) == 0 || len(it.Value) < minRedactLen {
			continue
		}
		itemForms[i] = buildForms(it.Value)
		totalForms += len(itemForms[i])
	}
	present := detectPresentForms(input, itemForms, totalForms)

	for itemIndex, it := range sorted {
		forms := itemForms[itemIndex]
		if len(forms) == 0 {
			continue
		}

		for formIndex, f := range forms {
			if present != nil && !present[itemIndex][formIndex] {
				continue
			}
			replaced, changed := replaceSpans(output, f.needle, f.marker)
			if changed {
				output = replaced
				redacted = true
				matched[it.Name] = struct{}{}
			}
		}
	}

	// Build sorted MatchedItems slice.
	var matchedItems []string
	for name := range matched {
		matchedItems = append(matchedItems, name)
	}
	sort.Strings(matchedItems)

	return Result{
		Output:       output,
		Redacted:     redacted,
		Suppressed:   false,
		MatchedItems: matchedItems,
	}
}

type formJob struct {
	itemIndex int
	formIndex int
	needle    []byte
}

func detectPresentForms(input []byte, itemForms [][]formDef, totalForms int) [][]bool {
	if len(input) < 1<<20 || totalForms < 512 {
		return nil
	}
	present := make([][]bool, len(itemForms))
	for i, forms := range itemForms {
		if len(forms) > 0 {
			present[i] = make([]bool, len(forms))
		}
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 2 {
		return nil
	}
	if workers > totalForms {
		workers = totalForms
	}
	jobs := make(chan formJob, workers*2)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if bytes.Contains(input, job.needle) {
					present[job.itemIndex][job.formIndex] = true
				}
			}
		}()
	}
	for itemIndex, forms := range itemForms {
		for formIndex, form := range forms {
			jobs <- formJob{itemIndex: itemIndex, formIndex: formIndex, needle: form.needle}
		}
	}
	close(jobs)
	wg.Wait()
	return present
}

// formDef pairs a needle with its redaction marker for a single encoding form.
type formDef struct {
	needle []byte
	marker []byte
}

// buildForms returns all (needle, marker) pairs for a secret value, using the
// same encoding forms as Apply. Empty needles are omitted.
func buildForms(val []byte) []formDef {
	defs := []formDef{
		{needle: val, marker: []byte("[REDACTED]")},
		{needle: []byte(base64.StdEncoding.EncodeToString(val)), marker: []byte("[REDACTED_B64]")},
		{needle: []byte(base64.URLEncoding.EncodeToString(val)), marker: []byte("[REDACTED_B64U]")},
		// Unpadded base64 — JWTs, Bearer tokens, and k8s/iOS exporters routinely
		// drop the '=' padding, so the padded forms above miss them.
		{needle: []byte(base64.RawStdEncoding.EncodeToString(val)), marker: []byte("[REDACTED_B64]")},
		{needle: []byte(base64.RawURLEncoding.EncodeToString(val)), marker: []byte("[REDACTED_B64U]")},
		{needle: []byte(hex.EncodeToString(val)), marker: []byte("[REDACTED_HEX]")},
		{needle: []byte(strings.ToUpper(hex.EncodeToString(val))), marker: []byte("[REDACTED_HEX]")},
		{needle: []byte(url.QueryEscape(string(val))), marker: []byte("[REDACTED_URL]")},
		// PathEscape encodes spaces as %20 (QueryEscape uses '+'); both appear in URLs.
		{needle: []byte(url.PathEscape(string(val))), marker: []byte("[REDACTED_URL]")},
		{needle: []byte(base32.StdEncoding.EncodeToString(val)), marker: []byte("[REDACTED_B32]")},
		{needle: []byte(encodeHTMLEntity(val)), marker: []byte("[REDACTED_HTML]")},
		{needle: []byte(encodeDoublePercent(val)), marker: []byte("[REDACTED_DPE]")},
		{needle: []byte(encodeUnicodeEscape(val)), marker: []byte("[REDACTED_UNI]")},
	}
	if b, err := json.Marshal(string(val)); err == nil && len(b) >= 2 {
		defs = append(defs, formDef{needle: b[1 : len(b)-1], marker: []byte("[REDACTED_JSON]")})
	}
	out := defs[:0]
	for _, d := range defs {
		if len(d.needle) > 0 {
			out = append(out, d)
		}
	}
	return out
}

// encodeHTMLEntity encodes every byte of b as a hex HTML character reference.
// Example: 'A' (0x41) → "&#x41;".
func encodeHTMLEntity(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		fmt.Fprintf(&sb, "&#x%02X;", c)
	}
	return sb.String()
}

// encodeDoublePercent percent-encodes every byte of b, then percent-encodes
// the resulting '%' signs. Example: 'P' (0x50) → "%2550".
func encodeDoublePercent(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		fmt.Fprintf(&sb, "%%25%02X", c)
	}
	return sb.String()
}

// encodeUnicodeEscape encodes every rune of string(b) as a \uXXXX sequence
// (BMP only; supplementary-plane runes beyond MaxRune are skipped).
func encodeUnicodeEscape(b []byte) string {
	var sb strings.Builder
	for _, r := range string(b) {
		fmt.Fprintf(&sb, "\\u%04X", r)
	}
	return sb.String()
}

// replaceSpans replaces every non-overlapping occurrence of needle in input
// with replacement, returning the new slice and whether any replacement happened.
func replaceSpans(input, needle, replacement []byte) ([]byte, bool) {
	if len(needle) == 0 || !bytes.Contains(input, needle) {
		return input, false
	}
	nLen := len(needle)
	var out []byte
	src := input
	for {
		idx := bytes.Index(src, needle)
		if idx < 0 {
			out = append(out, src...)
			break
		}
		out = append(out, src[:idx]...)
		out = append(out, replacement...)
		src = src[idx+nLen:]
	}
	return out, true
}
