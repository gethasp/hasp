package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveReferencesAndResolveReferenceItem(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	projectRoot := t.TempDir()
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert api_token: %v", err)
	}
	if _, err := handle.UpsertItem("db_url", ItemKindKV, []byte("postgres://localhost"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert db_url: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{
		"secret_01": "api_token",
		"secret_02": "db_url",
	}, PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	resolved, err := handle.ResolveReferences(context.Background(), projectRoot, []string{"secret_01", "secret_02"})
	if err != nil {
		t.Fatalf("resolve references: %v", err)
	}
	if len(resolved) != 2 {
		t.Fatalf("resolved len = %d, want 2", len(resolved))
	}
	item, err := handle.ResolveReferenceItem(context.Background(), projectRoot, "secret_01")
	if err != nil {
		t.Fatalf("resolve reference item: %v", err)
	}
	if item.Name != "api_token" {
		t.Fatalf("resolved item name = %q", item.Name)
	}

	named, err := handle.ResolveReference(context.Background(), projectRoot, "@db_url")
	if err != nil {
		t.Fatalf("resolve named reference: %v", err)
	}
	if named.Alias != "secret_02" || named.NamedReference != "@db_url" || named.ItemName != "db_url" {
		t.Fatalf("unexpected named reference resolution %+v", named)
	}
}

func TestResolveReferencesFailsForUnknownReference(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := handle.ResolveReferences(context.Background(), t.TempDir(), []string{"missing"}); err == nil || !errors.Is(err, ErrReferenceNotFound) {
		t.Fatalf("expected reference-not-found, got %v", err)
	}
}

func TestResolveReferenceDistinguishesNamedReferenceThatIsNotExposed(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	projectRoot := t.TempDir()
	if _, err := handle.UpsertItem("GEMINI_RAI_KEY", ItemKindKV, []byte("gemini-raw-secret-value"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert GEMINI_RAI_KEY: %v", err)
	}

	_, err = handle.ResolveReference(context.Background(), projectRoot, "@GEMINI_RAI_KEY")
	if err == nil {
		t.Fatal("expected named reference to fail when item is not exposed to the project")
	}
	if !errors.Is(err, ErrReferenceNotExposed) {
		t.Fatalf("expected not-exposed sentinel, got %v", err)
	}
	if !errors.Is(err, ErrReferenceNotFound) {
		t.Fatalf("expected not-exposed error to remain reference-not-found compatible, got %v", err)
	}

	var refErr *ReferenceNotExposedError
	if !errors.As(err, &refErr) {
		t.Fatalf("expected typed not-exposed error, got %T", err)
	}
	if refErr.Reference != "@GEMINI_RAI_KEY" || refErr.ItemName != "GEMINI_RAI_KEY" {
		t.Fatalf("unexpected not-exposed metadata: %+v", refErr)
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "@GEMINI_RAI_KEY") {
		t.Fatalf("expected safe reference metadata in error, got %q", got)
	}
	if strings.Contains(err.Error(), "gemini-raw-secret-value") {
		t.Fatalf("error must not include raw secret value: %q", err)
	}
	if strings.Contains(err.Error(), projectRoot) {
		t.Fatalf("error must not include project root: %q", err)
	}
}

func TestResolveReferencesPreservesNamedReferenceNotExposedDetails(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	projectRoot := t.TempDir()
	if _, err := handle.UpsertItem("GEMINI_RAI_KEY", ItemKindKV, []byte("gemini-raw-secret-value"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert GEMINI_RAI_KEY: %v", err)
	}

	_, err = handle.ResolveReferences(context.Background(), projectRoot, []string{"@GEMINI_RAI_KEY"})
	if err == nil {
		t.Fatal("expected batch resolve to fail for a named reference that is not exposed")
	}
	if !errors.Is(err, ErrReferenceNotExposed) {
		t.Fatalf("expected not-exposed sentinel, got %v", err)
	}

	var refErr *ReferenceNotExposedError
	if !errors.As(err, &refErr) {
		t.Fatalf("expected typed not-exposed error, got %T", err)
	}
	if refErr.Reference != "@GEMINI_RAI_KEY" || refErr.ItemName != "GEMINI_RAI_KEY" {
		t.Fatalf("unexpected not-exposed metadata: %+v", refErr)
	}
}

func TestReferenceNotExposedErrorMessageEdges(t *testing.T) {
	cases := []struct {
		name string
		err  *ReferenceNotExposedError
		want string
	}{
		{name: "nil", err: nil, want: ErrReferenceNotExposed.Error()},
		{name: "item", err: &ReferenceNotExposedError{ItemName: "TOKEN"}, want: `item "TOKEN"`},
		{name: "mismatch", err: &ReferenceNotExposedError{Reference: "@ALIAS", ItemName: "TOKEN"}, want: `reference "@ALIAS" item "TOKEN"`},
		{name: "empty", err: &ReferenceNotExposedError{}, want: ErrReferenceNotExposed.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); !strings.Contains(got, tc.want) {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestImportEnvFileHandlesExportsCommentsAndQuotes(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	envPath := filepath.Join(t.TempDir(), ".env")
	data := "# comment\nexport API_TOKEN=\"abc123\\\"\"\nDATABASE_URL='postgres://localhost'\nTRAILING_QUOTE=plain'\n\n"
	if err := os.WriteFile(envPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	items, err := handle.ImportEnvFile(envPath)
	if err != nil {
		t.Fatalf("import env: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 imported items, got %d", len(items))
	}
	apiToken, err := handle.GetItem("API_TOKEN")
	if err != nil || string(apiToken.Value) != "abc123\"" {
		t.Fatalf("expected quoted export value to import cleanly, got %+v err=%v", apiToken, err)
	}
	databaseURL, err := handle.GetItem("DATABASE_URL")
	if err != nil || string(databaseURL.Value) != "postgres://localhost" {
		t.Fatalf("expected single-quoted value to import cleanly, got %+v err=%v", databaseURL, err)
	}
	trailingQuote, err := handle.GetItem("TRAILING_QUOTE")
	if err != nil || string(trailingQuote.Value) != "plain'" {
		t.Fatalf("expected plain trailing quote to survive import, got %+v err=%v", trailingQuote, err)
	}
}

func TestImportJSONCredentialDerivesNameAndRejectsMalformedJSON(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	jsonPath := filepath.Join(t.TempDir(), "service-account.json")
	if err := os.WriteFile(jsonPath, []byte(`{"client_email":"ops@gethasp.com"}`), 0o600); err != nil {
		t.Fatalf("write json: %v", err)
	}
	item, err := handle.ImportJSONCredential(jsonPath, "")
	if err != nil {
		t.Fatalf("import json credential: %v", err)
	}
	if item.Name != "service-account" {
		t.Fatalf("expected derived item name, got %q", item.Name)
	}

	badPath := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write malformed json: %v", err)
	}
	if _, err := handle.ImportJSONCredential(badPath, "broken"); err == nil {
		t.Fatal("expected malformed JSON import to fail")
	}
}

func TestResolveReferenceCoversBlankAmbiguousAndMissingTarget(t *testing.T) {
	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	projectRoot := t.TempDir()
	if _, err := handle.UpsertItem("api_token", ItemKindKV, []byte("abc123"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert api_token: %v", err)
	}
	if _, err := handle.UpsertItem("db_url", ItemKindKV, []byte("postgres://localhost"), ItemMetadata{}); err != nil {
		t.Fatalf("upsert db_url: %v", err)
	}
	if _, err := handle.UpsertBinding(context.Background(), projectRoot, map[string]string{
		"api_token": "db_url",
	}, PolicySession, false); err != nil {
		t.Fatalf("upsert binding: %v", err)
	}

	if _, err := handle.ResolveReference(context.Background(), projectRoot, ""); !errors.Is(err, ErrReferenceNotFound) {
		t.Fatalf("expected blank reference not found, got %v", err)
	}
	if _, err := handle.ResolveReference(context.Background(), projectRoot, "@"); !errors.Is(err, ErrReferenceNotFound) || errors.Is(err, ErrReferenceNotExposed) {
		t.Fatalf("expected malformed named reference to remain plain not-found, got %v", err)
	}
	resolved, err := handle.ResolveReference(context.Background(), projectRoot, "api_token")
	if err != nil {
		t.Fatalf("expected alias-style reference to resolve, got %v", err)
	}
	if resolved.ItemName != "db_url" || resolved.Alias != "api_token" {
		t.Fatalf("expected alias reference to resolve to db_url, got %+v", resolved)
	}
	named, err := handle.ResolveReference(context.Background(), projectRoot, "@db_url")
	if err != nil {
		t.Fatalf("expected named reference to resolve, got %v", err)
	}
	if named.Alias != "api_token" || named.NamedReference != "@db_url" {
		t.Fatalf("expected named reference to reuse alias api_token, got %+v", named)
	}
	if _, err := handle.ResolveReference(context.Background(), projectRoot, "@missing_item"); !errors.Is(err, ErrReferenceNotFound) || errors.Is(err, ErrReferenceNotExposed) {
		t.Fatalf("expected missing named reference to fail, got %v", err)
	}
	namedMissingRoot := t.TempDir()
	if _, err := handle.UpsertBinding(context.Background(), namedMissingRoot, map[string]string{
		"secret_01": "ghost_item",
	}, PolicySession, false); err != nil {
		t.Fatalf("upsert named-missing binding: %v", err)
	}
	if _, err := handle.ResolveReference(context.Background(), namedMissingRoot, "@ghost_item"); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("expected missing item via named reference, got %v", err)
	}
	missingRoot := t.TempDir()
	if _, err := handle.UpsertBinding(context.Background(), missingRoot, map[string]string{
		"secret_99": "missing_item",
	}, PolicySession, false); err != nil {
		t.Fatalf("upsert missing-item binding: %v", err)
	}
	if _, err := handle.ResolveReference(context.Background(), missingRoot, "secret_99"); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("expected missing item error, got %v", err)
	}
}
