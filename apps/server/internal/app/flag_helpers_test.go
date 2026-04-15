package app

import "testing"

func TestAliasAndMappingStringNil(t *testing.T) {
	var aliases aliasFlags
	if aliases.String() != "null" {
		t.Fatalf("expected null alias string, got %q", aliases.String())
	}
	var mappings mappingFlag
	if mappings.String() != "" {
		t.Fatalf("expected empty mapping string, got %q", mappings.String())
	}

	var aliasPtr *aliasFlags
	if aliasPtr.String() != "" {
		t.Fatalf("expected nil alias pointer string, got %q", aliasPtr.String())
	}
	var mappingPtr *mappingFlag
	if mappingPtr.String() != "" {
		t.Fatalf("expected nil mapping pointer string, got %q", mappingPtr.String())
	}
}
