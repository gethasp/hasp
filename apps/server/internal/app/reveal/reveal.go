package reveal

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

type Payload struct {
	ID        string
	Name      string
	Kind      store.ItemKind
	Value     []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Request struct {
	Ref string
}

type Deps struct {
	Find      func(context.Context, string) (Payload, error)
	Authorize func(context.Context, Payload) error
	Audit     func(context.Context, Payload) error
}

func Run(ctx context.Context, req Request, deps Deps) (Payload, error) {
	ref := strings.TrimSpace(req.Ref)
	if ref == "" {
		return Payload{}, store.ErrItemNotFound
	}
	if deps.Find == nil {
		return Payload{}, errors.New("reveal: Find dependency is required")
	}
	payload, err := deps.Find(ctx, ref)
	if err != nil {
		return Payload{}, err
	}
	if deps.Authorize != nil {
		if err := deps.Authorize(ctx, payload); err != nil {
			return Payload{}, err
		}
	}
	if deps.Audit != nil {
		if err := deps.Audit(ctx, payload); err != nil {
			return Payload{}, err
		}
	}
	return payload, nil
}

func FromItem(item store.Item) Payload {
	return Payload{
		ID:        item.ID,
		Name:      item.Name,
		Kind:      item.Kind,
		Value:     append([]byte(nil), item.Value...),
		CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt,
	}
}

func Find(handle *store.Handle, ref string) (Payload, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Payload{}, store.ErrItemNotFound
	}
	item, err := handle.GetItem(ref)
	if err == nil {
		return FromItem(item), nil
	}
	if !errors.Is(err, store.ErrItemNotFound) {
		return Payload{}, err
	}
	for _, candidate := range handle.ListItems() {
		if candidate.ID == ref {
			return FromItem(candidate), nil
		}
	}
	return Payload{}, store.ErrItemNotFound
}
