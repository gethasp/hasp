package reveal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/paths"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func TestRunAndFindRevealPayloads(t *testing.T) {
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	item := store.Item{ID: "item-1", Name: "api", Kind: store.ItemKindKV, Value: []byte("secret"), CreatedAt: now, UpdatedAt: now}
	payload, err := Run(context.Background(), Request{Ref: " api "}, Deps{
		Find: func(_ context.Context, ref string) (Payload, error) {
			if ref != "api" {
				t.Fatalf("ref = %q", ref)
			}
			return FromItem(item), nil
		},
		Authorize: func(context.Context, Payload) error { return nil },
		Audit:     func(context.Context, Payload) error { return nil },
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if payload.Name != "api" || string(payload.Value) != "secret" {
		t.Fatalf("payload = %+v", payload)
	}
	payload.Value[0] = 'X'
	if string(item.Value) != "secret" {
		t.Fatal("payload did not clone item value")
	}

	if _, err := Run(context.Background(), Request{}, Deps{}); !errors.Is(err, store.ErrItemNotFound) {
		t.Fatalf("blank ref err = %v", err)
	}
	if _, err := Run(context.Background(), Request{Ref: "api"}, Deps{}); err == nil {
		t.Fatal("expected missing find dependency")
	}
	if _, err := Run(context.Background(), Request{Ref: "api"}, Deps{Find: func(context.Context, string) (Payload, error) {
		return Payload{}, errors.New("find failed")
	}}); err == nil {
		t.Fatal("expected find failure")
	}
	if _, err := Run(context.Background(), Request{Ref: "api"}, Deps{
		Find:      func(context.Context, string) (Payload, error) { return Payload{}, nil },
		Authorize: func(context.Context, Payload) error { return errors.New("denied") },
	}); err == nil {
		t.Fatal("expected authorize failure")
	}
	if _, err := Run(context.Background(), Request{Ref: "api"}, Deps{
		Find:  func(context.Context, string) (Payload, error) { return Payload{}, nil },
		Audit: func(context.Context, Payload) error { return errors.New("audit failed") },
	}); err == nil {
		t.Fatal("expected audit failure")
	}
}

func TestFindByNameAndID(t *testing.T) {
	t.Setenv(paths.EnvHome, t.TempDir())
	vault, err := store.New(nil)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := vault.Init(context.Background(), "correct horse battery staple"); err != nil {
		t.Fatalf("init: %v", err)
	}
	handle, err := vault.OpenWithPassword(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	item, err := handle.UpsertItem("api", store.ItemKindKV, []byte("secret"), store.ItemMetadata{})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	byName, err := Find(handle, " api ")
	if err != nil {
		t.Fatalf("find by name: %v", err)
	}
	byID, err := Find(handle, item.ID)
	if err != nil {
		t.Fatalf("find by id: %v", err)
	}
	if byName.ID != item.ID || byID.Name != "api" {
		t.Fatalf("find results byName=%+v byID=%+v", byName, byID)
	}
	if _, err := Find(handle, "missing"); !errors.Is(err, store.ErrItemNotFound) {
		t.Fatalf("missing err = %v", err)
	}
	if _, err := Find(handle, " "); !errors.Is(err, store.ErrItemNotFound) {
		t.Fatalf("blank err = %v", err)
	}
}
