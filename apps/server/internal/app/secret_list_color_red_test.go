package app

// RED tests for hasp-xbdr — color the per-row state badge in
// `hasp secret list`. Contract pinned:
//
//   - When ui.ColorOptions allow color, each secret row carries a state badge:
//     green "[vault-only]" when Exposures is empty, yellow "[shared]" when
//     it has at least one exposure.
//   - When the writer is non-interactive (bytes.Buffer in tests) the badge
//     still appears but as plain text — no ANSI sequences.
//   - Existing renderSecretList output (lead, secret name, kind) is preserved
//     so the higher-level cli_output styling layer keeps its contract.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/app/ui"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestSecretListShowsVaultOnlyBadgeGreenWhenColored(t *testing.T) {
	secrets := []secretMetadataView{
		{
			Name:           "API_TOKEN",
			NamedReference: store.NamedReference("API_TOKEN"),
			Kind:           "secret",
			CreatedAt:      "2026-01-01T00:00:00Z",
			UpdatedAt:      "2026-01-01T00:00:00Z",
		},
	}
	var buf bytes.Buffer
	if err := renderSecretListWithColor(&buf, secrets, ui.ColorOptions{Interactive: true}); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "vault-only") {
		t.Fatalf("expected 'vault-only' badge, got %q", out)
	}
	if !strings.Contains(out, "\x1b[32m") {
		t.Fatalf("expected green ANSI sequence for vault-only, got %q", out)
	}
}

func TestSecretListShowsSharedBadgeYellowWhenExposed(t *testing.T) {
	secrets := []secretMetadataView{
		{
			Name:           "API_TOKEN",
			NamedReference: store.NamedReference("API_TOKEN"),
			Kind:           "secret",
			CreatedAt:      "2026-01-01T00:00:00Z",
			UpdatedAt:      "2026-01-01T00:00:00Z",
			Exposures: []store.ItemExposure{
				{Reference: "@API_TOKEN", ProjectRoot: "/tmp/repo"},
			},
		},
	}
	var buf bytes.Buffer
	if err := renderSecretListWithColor(&buf, secrets, ui.ColorOptions{Interactive: true}); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "shared") {
		t.Fatalf("expected 'shared' badge, got %q", out)
	}
	if !strings.Contains(out, "\x1b[33m") {
		t.Fatalf("expected yellow ANSI sequence for shared, got %q", out)
	}
}

func TestSecretListPlainBadgeWhenNonInteractive(t *testing.T) {
	secrets := []secretMetadataView{
		{
			Name:           "API_TOKEN",
			NamedReference: store.NamedReference("API_TOKEN"),
			Kind:           "secret",
		},
	}
	var buf bytes.Buffer
	if err := renderSecretListWithColor(&buf, secrets, ui.ColorOptions{Interactive: false}); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "vault-only") {
		t.Fatalf("expected 'vault-only' label even in plain mode, got %q", out)
	}
	if strings.Contains(out, "\x1b[32m") || strings.Contains(out, "\x1b[33m") {
		t.Fatalf("expected no ANSI sequences in non-interactive mode, got %q", out)
	}
}

func TestSecretListPreservesExistingHeader(t *testing.T) {
	secrets := []secretMetadataView{
		{Name: "API_TOKEN", NamedReference: store.NamedReference("API_TOKEN"), Kind: "secret"},
	}
	var buf bytes.Buffer
	if err := renderSecretListWithColor(&buf, secrets, ui.ColorOptions{Interactive: false}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "Vault secrets") {
		t.Fatalf("expected 'Vault secrets' header preserved, got %q", buf.String())
	}
}
