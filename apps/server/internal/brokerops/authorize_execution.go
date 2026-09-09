package brokerops

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

type ReferenceAccess struct {
	Reference string
	Operation store.Operation
}

type ReferenceBatchAuthorizer func(context.Context, *store.Handle, string, string, string, []ReferenceAccess, store.GrantScope, store.GrantScope, time.Duration) ([]store.Item, error)

func AuthorizeReferences(ctx context.Context, handle *store.Handle, bindingID, projectRoot, sessionToken string, refs []ReferenceAccess, projectGrant, secretGrant store.GrantScope, window time.Duration) ([]store.Item, error) {
	items := make([]store.Item, 0, len(refs))
	requests := make([]store.AccessRequest, 0, len(refs))
	for _, ref := range refs {
		resolved, err := resolveReferenceFn(handle, ctx, projectRoot, ref.Reference)
		if err != nil {
			if errors.Is(err, store.ErrReferenceNotFound) && !errors.Is(err, store.ErrReferenceNotExposed) {
				return nil, fmt.Errorf("%w; env/files require an exposed @NAME or repo alias; use --literal-env (MCP literal_env) only for explicit configuration values", err)
			}
			return nil, err
		}
		item, err := getItemFn(handle, resolved.ItemName)
		if err != nil {
			return nil, err
		}
		if ref.Operation == store.OperationRun && item.Kind == store.ItemKindFile {
			return nil, fmt.Errorf("env delivery requires kv secret %q; use --file (MCP files) for a temporary file path", item.Name)
		}
		items = append(items, item)
		requests = append(requests, store.AccessRequest{
			Operation: ref.Operation, BindingID: bindingID, SessionToken: sessionToken,
			ItemName: item.Name, Policy: item.Metadata.Policy, Aliases: []string{ref.Reference},
		})
	}
	if len(requests) == 0 {
		requests = append(requests, store.AccessRequest{Operation: store.OperationList, BindingID: bindingID, SessionToken: sessionToken})
	}

	// Each request can need a secret grant, and the operation can need one
	// project lease. Repeating a denied requirement cannot mint another once
	// grant: those grants remain one-shot for the same session and item.
	granted := make(map[string]bool)
	for {
		decisions, err := authorizeBatchAndConsumeFn(handle, requests)
		if err != nil {
			return nil, err
		}
		pending := -1
		for i, decision := range decisions {
			if !decision.Allowed {
				pending = i
				break
			}
		}
		if pending == -1 {
			return items, nil
		}
		decision, req := decisions[pending], requests[pending]
		if !decision.RequiresPrompt {
			return nil, NewAuthorizationError(handle, req, decision)
		}
		key := string(decision.RequiredAction())
		if decision.RequiredAction() == store.AccessRequirementSecretGrant {
			key += ":" + req.ItemName
		}
		if granted[key] {
			return nil, NewAuthorizationError(handle, req, decision)
		}
		granted[key] = true
		switch decision.RequiredAction() {
		case store.AccessRequirementProjectLease:
			if projectGrant == "" {
				return nil, NewAuthorizationError(handle, req, decision)
			}
			if _, err := grantProjectLeaseFn(handle, bindingID, sessionToken, projectGrant, window); err != nil {
				return nil, err
			}
		case store.AccessRequirementSecretGrant:
			if secretGrant == "" {
				return nil, NewAuthorizationError(handle, req, decision)
			}
			relaxed := req.Policy == store.PolicyAccess && secretGrant == store.GrantWindow
			if _, err := grantSecretUseFn(handle, bindingID, sessionToken, req.ItemName, secretGrant, window, relaxed); err != nil {
				return nil, err
			}
		default:
			return nil, NewAuthorizationError(handle, req, decision)
		}
	}
}
