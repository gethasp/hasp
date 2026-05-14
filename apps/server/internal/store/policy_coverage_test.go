package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyValidationResidualBranches(t *testing.T) {
	baseMatch := PolicyMatch{Consumer: "agent", Secret: "secret", Scope: "window"}
	for _, tc := range []struct {
		name string
		doc  PolicyDocument
	}{
		{name: "missing id", doc: PolicyDocument{Rules: []PolicyRule{{Match: baseMatch, Decision: "allow"}}}},
		{name: "duplicate id", doc: PolicyDocument{Rules: []PolicyRule{{ID: "same", Match: baseMatch, Decision: "allow"}, {ID: "same", Match: PolicyMatch{Consumer: "agent2", Secret: "secret", Scope: "window"}, Decision: "allow"}}}},
		{name: "missing match", doc: PolicyDocument{Rules: []PolicyRule{{ID: "missing-match", Match: PolicyMatch{Consumer: "agent"}, Decision: "allow"}}}},
		{name: "bad decision", doc: PolicyDocument{Rules: []PolicyRule{{ID: "bad-decision", Match: baseMatch, Decision: "maybe"}}}},
		{name: "negative ttl", doc: PolicyDocument{Rules: []PolicyRule{{ID: "negative-ttl", Match: baseMatch, Decision: "allow", TTLS: -1}}}},
		{name: "negative max", doc: PolicyDocument{Rules: []PolicyRule{{ID: "negative-max", Match: baseMatch, Decision: "allow", MaxConcurrent: -1}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePolicy(tc.doc); !errors.Is(err, ErrPolicyInvalid) {
				t.Fatalf("ValidatePolicy err = %v, want ErrPolicyInvalid", err)
			}
		})
	}
	doc := normalizePolicyDocument(PolicyDocument{
		Version:   "  ",
		UpdatedBy: "  ",
		Rules: []PolicyRule{{
			ID:       " id ",
			Match:    PolicyMatch{Consumer: " agent ", Secret: " secret ", Scope: " window "},
			Decision: " allow ",
		}},
	})
	if doc.Version != "0" || doc.UpdatedBy != "system" || doc.Rules[0].ID != "id" || !strings.EqualFold(doc.Rules[0].Decision, "allow") {
		t.Fatalf("normalized policy = %+v", doc)
	}
}

func TestReplacePolicyResidualBranches(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	valid := PolicyDocument{Rules: []PolicyRule{{ID: "allow", Match: PolicyMatch{Consumer: "agent", Secret: "secret", Scope: "window"}, Decision: "allow"}}}
	if _, err := handle.ReplacePolicy(valid, "wrong-version", false, ""); !errors.Is(err, ErrPolicyVersionConflict) {
		t.Fatalf("version conflict err = %v", err)
	}
	if _, err := handle.ReplacePolicy(PolicyDocument{Rules: []PolicyRule{{ID: "bad"}}}, "0", true, ""); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("invalid policy err = %v", err)
	}
	updated, err := handle.ReplacePolicy(valid, "0", true, " daemon ")
	if err != nil {
		t.Fatalf("replace policy: %v", err)
	}
	if updated.UpdatedBy != "daemon" {
		t.Fatalf("updated by = %q", updated.UpdatedBy)
	}

	missingState := *handle
	missingState.store = &Store{paths: store.paths, keyring: store.keyring, audit: store.audit, now: store.now}
	missingState.store.paths.StatePath = filepath.Join(t.TempDir(), "missing.json")
	if _, err := missingState.ReplacePolicy(valid, "0", true, ""); err == nil {
		t.Fatal("expected missing policy state failure")
	}
	wrongKey := *handle
	wrongKey.vaultKey = make([]byte, keyLength)
	if _, err := wrongKey.ReplacePolicy(valid, updated.Version, true, ""); err == nil {
		t.Fatal("expected policy read state failure")
	}

	oldRandRead := randReadFn
	randReadFn = func([]byte) (int, error) { return 0, errors.New("random policy failed") }
	if _, err := handle.ReplacePolicy(valid, updated.Version, true, ""); err == nil {
		t.Fatal("expected policy version random failure")
	}
	randReadFn = oldRandRead
	t.Cleanup(func() { randReadFn = oldRandRead })

	oldMarshal := jsonMarshalFn
	jsonMarshalFn = func(any) ([]byte, error) { return nil, errors.New("persist policy failed") }
	if _, err := handle.ReplacePolicy(valid, updated.Version, true, ""); err == nil {
		t.Fatal("expected policy persist failure")
	}
	jsonMarshalFn = oldMarshal
	t.Cleanup(func() { jsonMarshalFn = oldMarshal })
}
