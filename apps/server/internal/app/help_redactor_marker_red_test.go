package app

// hasp-uhki: redactor markers are NOT length-preserving — a 4096-byte
// secret becomes "[REDACTED]" (10 bytes), so byte-position diff tools
// and column-aware log shippers see different offsets after redaction.
// Decision: keep the short, human-readable marker form. Document the
// non-preservation in `hasp help internals` so integrators don't ship
// pipelines that quietly assume offsets survive.

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestHelpInternalsDocumentsRedactorMarkerLengthSemantics(t *testing.T) {
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"help", "internals"}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("help internals: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"length-preserving",
		"[REDACTED]",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("`hasp help internals` must mention %q so integrators don't assume byte offsets survive redaction; got:\n%s", want, out)
		}
	}
}
