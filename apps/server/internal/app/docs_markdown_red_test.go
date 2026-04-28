package app

// RED tests for hasp-vl40 — `hasp docs markdown --out <path>`. Contract pinned:
//
//   - Renders every entry of helpTopicInventory as one combined markdown
//     reference page. Order matches the inventory so the page is reproducible.
//   - Emits a section header per topic (## hasp <topic>) followed by the
//     topic's text body inside a fenced code block (so leading spaces and
//     pipe characters survive).
//   - --out <path> is required; running without it errors with a usage hint.
//   - Writing succeeds even when the parent directory exists; the command
//     does not create directories.
//   - The combined output starts with a top-level "# HASP CLI reference"
//     heading and includes the build version.

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocsMarkdownWritesAllTopicsToFile(t *testing.T) {
	lockAppSeams(t)
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "cli.md")
	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"docs", "markdown", "--out", outPath}, bytes.NewBuffer(nil), &stdout, io.Discard); err != nil {
		t.Fatalf("docs markdown: %v", err)
	}
	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	text := string(body)
	if !strings.HasPrefix(text, "# HASP CLI reference") {
		head := text
		if len(head) > 120 {
			head = head[:120]
		}
		t.Fatalf("expected top-level heading, got prefix %q", head)
	}
	// Spot-check a handful of topics that must appear.
	for _, topic := range []string{"hasp setup", "hasp run", "hasp proof", "hasp internals"} {
		if !strings.Contains(text, "## "+topic) {
			t.Fatalf("expected `## %s` section in output", topic)
		}
	}
}

func TestDocsMarkdownRequiresOutFlag(t *testing.T) {
	lockAppSeams(t)
	if err := Run(context.Background(), []string{"docs", "markdown"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected error when --out is missing")
	}
}

func TestDocsMarkdownRejectsUnknownSubcommand(t *testing.T) {
	lockAppSeams(t)
	if err := Run(context.Background(), []string{"docs", "html"}, bytes.NewBuffer(nil), io.Discard, io.Discard); err == nil {
		t.Fatal("expected error for unsupported docs subcommand")
	}
}

func TestDocsMarkdownIncludesVersionInHeader(t *testing.T) {
	lockAppSeams(t)
	outPath := filepath.Join(t.TempDir(), "cli.md")
	if err := Run(context.Background(), []string{"docs", "markdown", "--out", outPath}, bytes.NewBuffer(nil), io.Discard, io.Discard); err != nil {
		t.Fatalf("docs markdown: %v", err)
	}
	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), "Build:") {
		t.Fatalf("expected 'Build:' line in markdown, got:\n%s", string(body)[:min(400, len(body))])
	}
}
