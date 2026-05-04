package profiles

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateRejectsMissingFields(t *testing.T) {
	profiles := []Profile{
		{},
		{ID: "id"},
		{ID: "id", Name: "name"},
		{ID: "id", Name: "name", Transport: "stdio"},
		{ID: "id", Name: "name", Transport: "stdio", Command: []string{"hasp", "mcp"}},
	}
	for _, profile := range profiles {
		if err := Validate(profile); err == nil {
			t.Fatalf("expected validation failure for %+v", profile)
		}
	}
}

func TestLoadDirRejectsMalformedProfileFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write malformed profile: %v", err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected malformed profile decode failure")
	}
}

func TestValidateAcceptsCompleteProfile(t *testing.T) {
	profile := Profile{
		ID:                   "codex",
		Name:                 "Codex",
		Transport:            "stdio",
		Command:              []string{"hasp", "mcp"},
		ProjectBindingRecipe: "manual",
		ApprovalPath:         "session",
		SafeInjectPath:       "inject",
		WriteEnvPath:         "write-env",
		RegressionFixture:    "apps/server/testdata/profiles/codex-cli.json",
		DocsPath:             "docs/agent-profiles/codex-cli.md",
	}
	if err := Validate(profile); err != nil {
		t.Fatalf("expected valid profile, got %v", err)
	}
}

func TestValidateRejectsEachRemainingRequiredField(t *testing.T) {
	base := Profile{
		ID:                   "id",
		Name:                 "name",
		Transport:            "stdio",
		Command:              []string{"hasp", "mcp"},
		ProjectBindingRecipe: "manual",
		ApprovalPath:         "session",
		SafeInjectPath:       "inject",
		WriteEnvPath:         "write-env",
		RegressionFixture:    "fixture",
		DocsPath:             "docs",
	}
	cases := []Profile{
		func() Profile { p := base; p.ApprovalPath = " "; return p }(),
		func() Profile { p := base; p.SafeInjectPath = " "; return p }(),
		func() Profile { p := base; p.WriteEnvPath = " "; return p }(),
		func() Profile { p := base; p.RegressionFixture = " "; return p }(),
		func() Profile { p := base; p.DocsPath = " "; return p }(),
	}
	for _, profile := range cases {
		if err := Validate(profile); err == nil {
			t.Fatalf("expected validation failure for %+v", profile)
		}
	}
}
