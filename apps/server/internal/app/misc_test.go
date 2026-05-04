package app

import (
	"testing"
)

func TestAliasFlagsAndMappingFlagHelpers(t *testing.T) {
	var aliases aliasFlags
	if err := aliases.Set("secret_01=api_token"); err != nil {
		t.Fatalf("alias set: %v", err)
	}
	if aliases.String() == "" {
		t.Fatal("expected alias string output")
	}
	if err := aliases.Set("bad-value"); err == nil {
		t.Fatal("expected alias parse error")
	}

	var mappings mappingFlag
	if err := mappings.Set("API_TOKEN=secret_01"); err != nil {
		t.Fatalf("mapping set: %v", err)
	}
	if mappings.String() == "" {
		t.Fatal("expected mapping string output")
	}
	if err := mappings.Set("bad"); err == nil {
		t.Fatal("expected mapping parse error")
	}
}
