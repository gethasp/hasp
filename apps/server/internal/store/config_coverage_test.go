package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConfigValidationBranches(t *testing.T) {
	spacedIdleRelockKey := " vault.idle_relock_s "
	doc := normalizeConfigDocument(ConfigDocument{
		spacedIdleRelockKey:                   float64(120),
		"integrations.disabled_targets":       []any{"mcp", "env-injection", "mcp"},
		"notifications.critical_consumer_ids": []any{"beta", "alpha", "beta", ""},
		"unknown":                             "ignored",
		"backup.retention_count":              "bad",
	})
	if doc["vault.idle_relock_s"] != 120 {
		t.Fatalf("idle relock = %#v", doc["vault.idle_relock_s"])
	}
	if got := doc["integrations.disabled_targets"]; !reflect.DeepEqual(got, []string{"env-injection", "mcp"}) {
		t.Fatalf("disabled targets = %#v", got)
	}
	if got := doc["notifications.critical_consumer_ids"]; !reflect.DeepEqual(got, []string{"alpha", "beta"}) {
		t.Fatalf("critical consumers = %#v", got)
	}
	if doc["backup.retention_count"] != 5 {
		t.Fatalf("invalid retention should default, got %#v", doc["backup.retention_count"])
	}

	assertConfigErr(t, validateBool("flag"), "yes")
	assertConfigErr(t, validateIntRange("count", 1, 3), "1")
	assertConfigErr(t, validateIntRange("count", 1, 3), 4)
	assertConfigErr(t, validateString("name", 3), 7)
	assertConfigErr(t, validateString("name", 3), strings.Repeat("x", 4))
	assertConfigErr(t, validateEnum("mode", []string{"on"}), true)
	assertConfigErr(t, validateEnum("mode", []string{"on"}), "off")
	assertConfigErr(t, validateStringSlice("targets", []string{"mcp"}), 1)
	assertConfigErr(t, validateStringSlice("targets", []string{"mcp"}), []any{"mcp", 1})
	assertConfigErr(t, validateStringSlice("targets", []string{"mcp"}), []string{""})
	assertConfigErr(t, validateStringSlice("targets", []string{"mcp"}), []string{"shell-hook"})
	assertConfigErr(t, validateAnyStringSlice("ids"), 1)
	assertConfigErr(t, validateAnyStringSlice("ids"), []any{"ok", 1})

	if got, ok := intFromConfigValue(float64(1.5)); ok || got != 0 {
		t.Fatalf("fractional float = %d ok=%t", got, ok)
	}
	if got, ok := intFromConfigValue(int64(1)); !ok || got != 1 {
		t.Fatalf("int64 = %d ok=%t", got, ok)
	}
	oldBounds := configIntBounds
	defer func() { configIntBounds = oldBounds }()
	configIntBounds = func() (int64, int64) { return -1, 1 }
	if got, ok := intFromConfigValue(int64(2)); ok || got != 0 {
		t.Fatalf("overflow int64 = %d ok=%t", got, ok)
	}
	if got, ok := intFromConfigValue(struct{}{}); ok || got != 0 {
		t.Fatalf("unsupported int type = %d ok=%t", got, ok)
	}

	rawAny := []any{"a"}
	clonedAny := cloneConfigValue(rawAny).([]any)
	clonedAny[0] = "b"
	if rawAny[0] != "a" {
		t.Fatal("cloneConfigValue should clone []any")
	}
}

func TestConfigAccessAndMutationResidualBranches(t *testing.T) {
	custom, err := NewForPaths(nil, newTestStore(t).paths)
	if err != nil {
		t.Fatalf("new for paths: %v", err)
	}
	if custom.now().IsZero() {
		t.Fatal("new for paths now returned zero time")
	}

	store := newTestStore(t)
	if err := store.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init store: %v", err)
	}
	handle, err := store.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	value, err := handle.GetConfigValue("notifications.critical_consumer_ids")
	if err != nil {
		t.Fatalf("get config value: %v", err)
	}
	cloned := value.([]string)
	cloned = append(cloned, "mutated")
	if len(cloned) != 1 {
		t.Fatalf("mutated clone = %#v", cloned)
	}
	again, err := handle.GetConfigValue("notifications.critical_consumer_ids")
	if err != nil {
		t.Fatalf("get config value again: %v", err)
	}
	if len(again.([]string)) != 0 {
		t.Fatalf("config value was not cloned: %#v", again)
	}
	if _, err := handle.SetConfigValue("vault.idle_relock_s", 120, " daemon "); err != nil {
		t.Fatalf("set config with actor: %v", err)
	}

	missingState := *handle
	missingState.store = &Store{paths: store.paths, keyring: store.keyring, audit: store.audit, now: store.now}
	missingState.store.paths.StatePath = filepath.Join(t.TempDir(), "missing.json")
	if _, err := missingState.SetConfigValue("vault.idle_relock_s", 120); err == nil {
		t.Fatal("expected missing state read failure")
	}
	wrongKey := *handle
	wrongKey.vaultKey = make([]byte, keyLength)
	if _, err := wrongKey.SetConfigValue("vault.idle_relock_s", 120); err == nil {
		t.Fatal("expected config read state failure")
	}

	oldMarshal := jsonMarshalFn
	jsonMarshalFn = func(any) ([]byte, error) { return nil, errors.New("persist config failed") }
	if _, err := handle.SetConfigValue("vault.idle_relock_s", 180); err == nil {
		t.Fatal("expected config persist failure")
	}
	jsonMarshalFn = oldMarshal
	t.Cleanup(func() { jsonMarshalFn = oldMarshal })
}

func assertConfigErr(t *testing.T, validate func(any) (any, error), value any) {
	t.Helper()
	if _, err := validate(value); !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("validate(%#v) err = %v, want ErrConfigInvalid", value, err)
	}
}
