package store

import (
	"context"
	"errors"
	"testing"
)

func TestItemExposuresHideAndDeleteCleanup(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	repoA := t.TempDir()
	repoB := t.TempDir()
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert item: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), repoA, map[string]string{"secret_02": "api_token", "secret_01": "api_token", "secret_03": "db_url"}, PolicySession, false); err != nil {
		t.Fatalf("upsert binding A: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), repoB, map[string]string{"secret_02": "api_token"}, PolicySession, false); err != nil {
		t.Fatalf("upsert binding B: %v", err)
	}
	repoC := t.TempDir()
	if _, err := handle.UpsertBinding(context.Background(), repoC, nil, PolicySession, false); err != nil {
		t.Fatalf("upsert binding C: %v", err)
	}
	if _, err := handle.UpsertItem("db_url", ItemKindKV, []byte("postgres://localhost"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert second item: %v", err)
	}
	repoD := t.TempDir()
	if _, err := handle.UpsertBinding(context.Background(), repoD, map[string]string{"secret_03": "db_url"}, PolicySession, false); err != nil {
		t.Fatalf("upsert binding D: %v", err)
	}
	if exposures := handle.ItemExposures("missing"); len(exposures) != 0 {
		t.Fatalf("expected no exposures for missing item, got %+v", exposures)
	}

	exposures := handle.ItemExposures("api_token")
	if len(exposures) != 3 {
		t.Fatalf("expected two exposures, got %+v", exposures)
	}
	canonicalRepoA, err := CanonicalProjectRoot(context.Background(), repoA)
	if err != nil {
		t.Fatalf("canonical repoA: %v", err)
	}
	if exposures[0].ProjectRoot != canonicalRepoA || exposures[0].Reference != "secret_01" || exposures[1].ProjectRoot != canonicalRepoA || exposures[1].Reference != "secret_02" {
		t.Fatalf("expected same-root exposures sorted by reference, got %+v", exposures)
	}

	removed, err := handle.HideItemFromProject(context.Background(), repoA, "api_token")
	if err != nil {
		t.Fatalf("hide item from project: %v", err)
	}
	if len(removed) != 2 || removed[0] != "secret_01" || removed[1] != "secret_02" {
		t.Fatalf("unexpected removed refs: %+v", removed)
	}
	removed, err = handle.HideItemFromProject(context.Background(), repoA, "api_token")
	if err != nil {
		t.Fatalf("hide already-hidden item from project: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("expected no refs removed on second hide, got %+v", removed)
	}
	exposures = handle.ItemExposures("api_token")
	canonicalRepoB, err := CanonicalProjectRoot(context.Background(), repoB)
	if err != nil {
		t.Fatalf("canonical repoB: %v", err)
	}
	if len(exposures) != 1 || exposures[0].ProjectRoot != canonicalRepoB {
		t.Fatalf("expected only repoB exposure to remain, got %+v", exposures)
	}

	if err := handle.DeleteItem("api_token"); err != nil {
		t.Fatalf("delete item: %v", err)
	}
	exposures = handle.ItemExposures("api_token")
	if len(exposures) != 0 {
		t.Fatalf("expected delete to clear all exposures, got %+v", exposures)
	}
	if _, err := handle.ResolveReference(context.Background(), repoB, "secret_02"); !errors.Is(err, ErrReferenceNotFound) {
		t.Fatalf("expected repo ref to be invalidated after delete, got %v", err)
	}
	if removedCount := handle.removeItemFromBindings("missing"); removedCount != 0 {
		t.Fatalf("expected no binding removals for missing item, got %d", removedCount)
	}
	if removed, err := handle.HideItemFromProject(context.Background(), t.TempDir(), "api_token"); err != nil || len(removed) != 0 {
		t.Fatalf("expected hide on unknown repo to noop, got removed=%+v err=%v", removed, err)
	}

	origAbs := filepathAbsFn
	defer func() { filepathAbsFn = origAbs }()
	filepathAbsFn = func(string) (string, error) { return "", errors.New("abs fail") }
	if _, err := handle.HideItemFromProject(context.Background(), repoB, "db_url"); err == nil || err.Error() != "resolve project path: abs fail" {
		t.Fatalf("expected hide canonicalization failure, got %v", err)
	}
}
