package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// hasp-q1jm: 'hasp list' was a shortcut for 'hasp secret list', but the tool
// also has 'hasp app list', 'hasp agent list', 'hasp project list', etc.
// A bare 'hasp list' implies "everything", not "secrets". Same applies to
// 'hasp get'. Both are now removed; users must scope by domain.

func TestTopLevelListShortcutRemoved(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)

	for _, spec := range rootCommandInventory() {
		if spec.name == "list" {
			t.Fatalf("hasp-q1jm: top-level 'list' shortcut must be removed; still present: %+v", spec)
		}
	}

	err := Run(context.Background(), []string{"list"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected 'hasp list' to error after shortcut removal")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected unknown-command error, got %v", err)
	}
}

func TestTopLevelGetShortcutRemoved(t *testing.T) {
	lockAppSeams(t)
	homeDir := t.TempDir()
	t.Setenv("HASP_HOME", homeDir)

	for _, spec := range rootCommandInventory() {
		if spec.name == "get" {
			t.Fatalf("hasp-q1jm: top-level 'get' shortcut must be removed; still present: %+v", spec)
		}
	}

	err := Run(context.Background(), []string{"get", "API_TOKEN"}, bytes.NewBuffer(nil), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected 'hasp get' to error after shortcut removal")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected unknown-command error, got %v", err)
	}
}
