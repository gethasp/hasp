package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestClassificationDefaultsPersistsAndResetsOnValueWrite(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.Init(ctx, "synthetic classification password"); err != nil {
		t.Fatal(err)
	}
	h, err := s.OpenWithPassword(ctx, "synthetic classification password")
	if err != nil {
		t.Fatal(err)
	}
	item, err := h.UpsertItem("PROJECT_ID", ItemKindKV, []byte("1234567890"), ItemMetadata{Policy: PolicySession})
	if err != nil || !item.Confidential() {
		t.Fatalf("new item not confidential: %+v %v", item, err)
	}
	for _, encoded := range []string{`{}`, `{"classification":"unknown"}`} {
		var old Item
		if err := json.Unmarshal([]byte(encoded), &old); err != nil {
			t.Fatal(err)
		}
		if !old.Confidential() {
			t.Fatal("old/unknown classification stopped protection")
		}
	}
	if _, err := h.SetItemClassification(item.Name, "public-id"); err == nil {
		t.Fatal("unknown classification accepted")
	}
	changed, err := h.SetItemClassification(item.Name, ClassificationConfiguration)
	if err != nil || changed.Confidential() || len(changed.Value) != 0 {
		t.Fatalf("classification result: %+v %v", changed, err)
	}
	h, err = s.OpenWithPassword(ctx, "synthetic classification password")
	if err != nil {
		t.Fatal(err)
	}
	item, err = h.GetItem(item.Name)
	if err != nil || item.Confidential() || string(item.Value) != "1234567890" || item.Metadata.Policy != PolicySession {
		t.Fatalf("classification changed value/access policy: %+v %v", item, err)
	}
	// Even an idempotent import requires another explicit classification.
	item, err = h.UpsertItem(item.Name, item.Kind, item.Value, item.Metadata)
	if err != nil || !item.Confidential() {
		t.Fatalf("upsert retained relaxed handling: %+v %v", item, err)
	}
	if _, err := h.SetItemClassification("missing", ClassificationConfiguration); err != ErrItemNotFound {
		t.Fatalf("missing item: %v", err)
	}
}

func TestClassificationRollbackOnPersistenceFailure(t *testing.T) {
	lockStoreSeams(t)
	s, h := openedCoverageStore(t)
	before, err := h.UpsertItem("PROJECT_ID", ItemKindKV, []byte("1234567890"), ItemMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("write unavailable")
	oldWrite := writeEnvelopeFileFn
	t.Cleanup(func() { writeEnvelopeFileFn = oldWrite })
	writeEnvelopeFileFn = func(string, []byte, os.FileMode) error { return want }
	if _, err := h.SetItemClassification(before.Name, ClassificationConfiguration); !errors.Is(err, want) {
		t.Fatalf("write failure: %v", err)
	}
	after, err := h.GetItem(before.Name)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("failed save changed in-memory item: %+v, %v", after, err)
	}
	writeEnvelopeFileFn = oldWrite
	reopened, err := s.OpenWithPassword(context.Background(), "coverage-password")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := reopened.GetItem(before.Name)
	if err != nil || !reflect.DeepEqual(stored, before) {
		t.Fatalf("failed save changed disk item: %+v, %v", stored, err)
	}
	if err := os.WriteFile(s.paths.StatePath, []byte("broken envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.SetItemClassification(before.Name, ClassificationConfiguration); err == nil {
		t.Fatal("classification accepted unreadable vault state")
	}
}

func TestAuthorizationBatchRejectsMixedAuthority(t *testing.T) {
	for _, requests := range [][]AccessRequest{
		nil,
		{{BindingID: "project-one", SessionToken: "session"}, {BindingID: "project-two", SessionToken: "session"}},
		{{BindingID: "project-one", SessionToken: "session-one"}, {BindingID: "project-one", SessionToken: "session-two"}},
	} {
		var h *Handle
		if _, err := h.AuthorizeBatchAndConsume(requests); err == nil {
			t.Fatalf("accepted invalid batch: %+v", requests)
		}
	}
}

func TestManifestLiteralEnvRejectsInvalidAndCaseCollidingNames(t *testing.T) {
	for _, literal := range []string{`{"BAD NAME":"value"}`, `{"CI":"1","ci":"2"}`} {
		data := []byte(`{"version":"v1","project":{"name":"fixture"},"targets":[{"name":"build","root":".","command":["true"],"literal_env":` + literal + `}]}`)
		if _, err := DecodeRepoManifest(t.TempDir(), data); err == nil {
			t.Fatalf("accepted literals: %s", literal)
		}
	}
}
