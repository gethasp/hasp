package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// hasp-y78u: deprecation notices respect --quiet and HASP_NO_DEPRECATION so
// scripts that wrap legacy commands can keep their stderr clean.

func TestEmitDeprecationWarningPrintsByDefault(t *testing.T) {
	var stderr bytes.Buffer
	emitDeprecationWarning(context.Background(), &stderr, "noisy %s\n", "thing")
	if got := stderr.String(); !strings.Contains(got, "noisy thing") {
		t.Fatalf("expected default emit, got %q", got)
	}
}

func TestEmitDeprecationWarningSuppressedByQuietFlag(t *testing.T) {
	ctx := contextWithGlobalFlags(context.Background(), globalFlags{quiet: true})
	var stderr bytes.Buffer
	emitDeprecationWarning(ctx, &stderr, "noisy %s\n", "thing")
	if stderr.Len() != 0 {
		t.Fatalf("expected silence under --quiet, got %q", stderr.String())
	}
}

func TestEmitDeprecationWarningSuppressedByEnvOptOut(t *testing.T) {
	t.Setenv("HASP_NO_DEPRECATION", "1")
	var stderr bytes.Buffer
	emitDeprecationWarning(context.Background(), &stderr, "noisy %s\n", "thing")
	if stderr.Len() != 0 {
		t.Fatalf("expected silence under HASP_NO_DEPRECATION=1, got %q", stderr.String())
	}
}

func TestDeprecationOptOutFromEnvAcceptsCanonicalTruthy(t *testing.T) {
	for _, on := range []string{"1", "true", "yes", "on", "TRUE", " on "} {
		if !deprecationOptOutFromEnv(on) {
			t.Errorf("expected %q to be a truthy opt-out", on)
		}
	}
	for _, off := range []string{"", "0", "false", "no", "off", "wat"} {
		if deprecationOptOutFromEnv(off) {
			t.Errorf("expected %q to leave deprecation prints intact", off)
		}
	}
}

// Integration: setCommand emits the deprecation banner by default but stays
// silent under --quiet. The setCommand body errors out shortly after the
// banner because no name/value were supplied, but stderr capture is what we
// care about here.
func TestSetCommandRespectsQuietForDeprecationBanner(t *testing.T) {
	var loud, quiet bytes.Buffer

	_ = setCommand(context.Background(), []string{}, nil, nil, &loud)
	if !strings.Contains(loud.String(), "deprecated") {
		t.Fatalf("expected default banner on stderr, got %q", loud.String())
	}

	ctx := contextWithGlobalFlags(context.Background(), globalFlags{quiet: true})
	_ = setCommand(ctx, []string{}, nil, nil, &quiet)
	if strings.Contains(quiet.String(), "deprecated") {
		t.Fatalf("expected --quiet to suppress deprecation banner, got %q", quiet.String())
	}
}
