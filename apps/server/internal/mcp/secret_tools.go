package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/app/auditlog"
	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/brokerops"
	"github.com/gethasp/hasp/apps/server/internal/projectcontext"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

var (
	upsertItemMCPFn    = (*store.Handle).UpsertItem
	bindItemAliasMCPFn = (*store.Handle).BindItemAlias
	hideItemMCPFn      = (*store.Handle).HideItemFromProject
	upsertBindingMCPFn = (*store.Handle).UpsertBinding
)

func callSecretAdd(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	return callSecretUpsert(ctx, handle, call, false)
}

func callSecretUpdate(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	return callSecretUpsert(ctx, handle, call, true)
}

func callSecretUpsert(ctx context.Context, handle *store.Handle, call toolCall, update bool) (map[string]any, error) {
	name := stringArg(call.Arguments, "name", "")
	value := stringArg(call.Arguments, "value", "")
	kind := store.ItemKind(stringArg(call.Arguments, "kind", string(store.ItemKindKV)))
	projectRoot := strings.TrimSpace(stringArg(call.Arguments, "project_root", defaultOptionalMCPProjectRoot()))
	expose := boolArg(call.Arguments, "expose", true)
	onConflict := strings.TrimSpace(stringArg(call.Arguments, "on_conflict", "error"))
	if name == "" {
		return nil, errors.New("name is required")
	}
	if value == "" {
		return nil, errors.New("value is required")
	}
	existing, err := getItemMCPFn(handle, name)
	exists := err == nil
	if err != nil && !errors.Is(err, store.ErrItemNotFound) {
		return nil, err
	}
	if update && !exists {
		return nil, store.ErrItemNotFound
	}
	if !update && exists {
		switch onConflict {
		case "replace":
			update = true
		case "skip":
			return map[string]any{
				"item_name":       name,
				"named_reference": store.NamedReference(name),
				"outcome":         "skipped",
			}, nil
		default:
			return nil, fmt.Errorf("secret %q already exists", name)
		}
	}
	hostLabel := defaultMCPHostLabel(call)
	if projectRoot != "" && expose {
		session, err := ensureSessionFn(ctx, projectRoot, defaultMCPSessionToken(call), hostLabel)
		if err != nil {
			return nil, err
		}
		binding, _, err := ensureProjectBindingExplicitMCP(ctx, handle, projectRoot)
		if err != nil {
			return nil, err
		}
		projectGrant, err := parseScope(stringArg(call.Arguments, "grant_project", ""), store.GrantOnce)
		if err != nil {
			return nil, err
		}
		secretGrant, err := parseScope(stringArg(call.Arguments, "grant_secret", ""), store.GrantOnce)
		if err != nil {
			return nil, err
		}
		grantWrite := boolArg(call.Arguments, "grant_write", false)
		creatingNew := !exists
		if err := brokerops.AuthorizeCapture(ctx, handle, binding.ID, session.Token, name, projectGrant, secretGrant, 15*time.Minute, grantWrite); err != nil {
			return nil, err
		}
		if creatingNew && grantWrite {
			appendAuditApproval(binding.ID, name)
		}
		result, err := captureMCPFn(handle, ctx, projectRoot, name, kind, []byte(value), true)
		if err != nil {
			return nil, err
		}
		outcome := "created"
		if update {
			outcome = "updated"
		}
		appendSecretAuditMCP(audit.EventCapture, hostLabel, map[string]any{
			"action":       "secret.upsert",
			"surface":      "mcp",
			"host_label":   hostLabel,
			"item_name":    result.ItemName,
			"item_kind":    result.ItemKind,
			"project_root": binding.CanonicalRoot,
			"reference":    result.Reference,
			"outcome":      outcome,
		})
		return map[string]any{
			"item_name":       result.ItemName,
			"item_kind":       result.ItemKind,
			"project_root":    binding.CanonicalRoot,
			"reference":       result.Reference,
			"named_reference": store.NamedReference(result.ItemName),
			"outcome":         outcome,
		}, nil
	}
	metadata := store.ItemMetadata{}
	if exists {
		metadata = existing.Metadata
		kind = existing.Kind
	}
	item, err := upsertItemMCPFn(handle, name, kind, []byte(value), metadata)
	if err != nil {
		return nil, err
	}
	outcome := "created"
	if update {
		outcome = "updated"
	}
	appendSecretAuditMCP(audit.EventCapture, hostLabel, map[string]any{
		"action":     "secret.upsert",
		"surface":    "mcp",
		"host_label": hostLabel,
		"item_name":  item.Name,
		"item_kind":  item.Kind,
		"outcome":    outcome,
	})
	return map[string]any{
		"item_name":       item.Name,
		"item_kind":       item.Kind,
		"named_reference": store.NamedReference(item.Name),
		"outcome":         outcome,
	}, nil
}

func callSecretDelete(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	name := stringArg(call.Arguments, "name", "")
	projectRoot := stringArg(call.Arguments, "project_root", defaultOptionalMCPProjectRoot())
	if name == "" {
		return nil, errors.New("name is required")
	}
	item, binding, err := authorizeSecretMutationMCP(ctx, handle, call, projectRoot, name, store.SecretMutationDelete)
	if err != nil {
		return nil, err
	}
	exposures := handle.ItemExposures(name)
	if err := handle.DeleteItem(name); err != nil {
		return nil, err
	}
	hostLabel := defaultMCPHostLabel(call)
	appendSecretAuditMCP("item.delete", hostLabel, map[string]any{
		"action":                "secret.delete",
		"surface":               "mcp",
		"host_label":            hostLabel,
		"item_name":             item.Name,
		"project_root":          binding.CanonicalRoot,
		"invalidated_exposures": len(exposures),
		"outcome":               "deleted",
	})
	return map[string]any{
		"item_name":             item.Name,
		"project_root":          binding.CanonicalRoot,
		"invalidated_exposures": len(exposures),
		"named_reference":       store.NamedReference(item.Name),
		"outcome":               "deleted",
	}, nil
}

func callSecretGet(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	name := stringArg(call.Arguments, "name", "")
	if name == "" {
		return nil, errors.New("name is required")
	}
	projectRoot := strings.TrimSpace(stringArg(call.Arguments, "project_root", defaultOptionalMCPProjectRoot()))
	if projectRoot == "" {
		return nil, errors.New("project_root is required")
	}
	_, binding, err := requireMCPProjectAuthorization(ctx, handle, call, projectRoot)
	if err != nil {
		return nil, err
	}
	item, err := getItemMCPFn(handle, name)
	if err != nil {
		if errors.Is(err, store.ErrItemNotFound) {
			return map[string]any{"name": name, "exists": false, "named_reference": store.NamedReference(name)}, nil
		}
		return nil, err
	}
	exposures := handle.ItemExposures(item.Name)
	available := false
	reference := ""
	for _, exposure := range exposures {
		if exposure.ProjectRoot == binding.CanonicalRoot {
			available = true
			reference = exposure.Reference
			break
		}
	}
	return map[string]any{
		"name":                 item.Name,
		"exists":               true,
		"kind":                 item.Kind,
		"created_at":           item.CreatedAt.Format(time.RFC3339),
		"updated_at":           item.UpdatedAt.Format(time.RFC3339),
		"available_in_project": available,
		"reference":            reference,
		"named_reference":      store.NamedReference(item.Name),
	}, nil
}

func callSecretExpose(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	name := stringArg(call.Arguments, "name", "")
	projectRoot := stringArg(call.Arguments, "project_root", defaultOptionalMCPProjectRoot())
	if name == "" || strings.TrimSpace(projectRoot) == "" {
		return nil, errors.New("project_root and name are required")
	}
	item, binding, err := authorizeSecretMutationMCP(ctx, handle, call, projectRoot, name, store.SecretMutationExpose)
	if err != nil {
		return nil, err
	}
	existing := existingExposureReferenceMCP(handle.ItemExposures(item.Name), binding.CanonicalRoot)
	reference, err := bindItemAliasMCPFn(handle, ctx, binding.CanonicalRoot, item.Name)
	if err != nil {
		return nil, err
	}
	outcome := "exposed"
	if existing != "" {
		outcome = "already_exposed"
	}
	hostLabel := defaultMCPHostLabel(call)
	appendSecretAuditMCP("binding.alias_bind", hostLabel, map[string]any{
		"action":       "secret.expose",
		"surface":      "mcp",
		"host_label":   hostLabel,
		"item_name":    item.Name,
		"project_root": binding.CanonicalRoot,
		"reference":    reference,
		"outcome":      outcome,
	})
	return map[string]any{
		"item_name":       item.Name,
		"project_root":    binding.CanonicalRoot,
		"reference":       reference,
		"named_reference": store.NamedReference(item.Name),
		"outcome":         outcome,
	}, nil
}

func callSecretHide(ctx context.Context, handle *store.Handle, call toolCall) (map[string]any, error) {
	name := stringArg(call.Arguments, "name", "")
	projectRoot := stringArg(call.Arguments, "project_root", defaultOptionalMCPProjectRoot())
	if name == "" || strings.TrimSpace(projectRoot) == "" {
		return nil, errors.New("project_root and name are required")
	}
	item, binding, err := authorizeSecretMutationMCP(ctx, handle, call, projectRoot, name, store.SecretMutationHide)
	if err != nil {
		return nil, err
	}
	removed, err := hideItemMCPFn(handle, ctx, binding.CanonicalRoot, item.Name)
	if err != nil {
		return nil, err
	}
	outcome := "already_hidden"
	if len(removed) > 0 {
		outcome = "hidden"
	}
	hostLabel := defaultMCPHostLabel(call)
	appendSecretAuditMCP("binding.alias_hide", hostLabel, map[string]any{
		"action":       "secret.hide",
		"surface":      "mcp",
		"host_label":   hostLabel,
		"item_name":    item.Name,
		"project_root": binding.CanonicalRoot,
		"references":   removed,
		"outcome":      outcome,
	})
	return map[string]any{
		"item_name":       item.Name,
		"project_root":    binding.CanonicalRoot,
		"references":      removed,
		"named_reference": store.NamedReference(item.Name),
		"outcome":         outcome,
	}, nil
}

func authorizeSecretMutationMCP(ctx context.Context, handle *store.Handle, call toolCall, projectRoot string, name string, action store.SecretMutationAction) (store.Item, store.Binding, error) {
	if strings.TrimSpace(projectRoot) == "" {
		return store.Item{}, store.Binding{}, errors.New("project_root and name are required")
	}
	item, err := getItemMCPFn(handle, name)
	if err != nil {
		return store.Item{}, store.Binding{}, err
	}
	hostLabel := defaultMCPHostLabel(call)
	session, err := ensureSessionFn(ctx, projectRoot, defaultMCPSessionToken(call), hostLabel)
	if err != nil {
		return store.Item{}, store.Binding{}, err
	}
	binding, _, err := ensureProjectBindingExplicitMCP(ctx, handle, projectRoot)
	if err != nil {
		return store.Item{}, store.Binding{}, err
	}
	if err := handle.ConsumeSecretMutationGrant(binding.ID, session.Token, item.Name, action); err != nil {
		return store.Item{}, store.Binding{}, err
	}
	appendAuditApproval(binding.ID, item.Name)
	return item, binding, nil
}

func ensureProjectBindingExplicitMCP(ctx context.Context, handle *store.Handle, projectRoot string) (store.Binding, []store.VisibleReference, error) {
	binding, visible, _, err := projectcontext.EnsureExplicit(ctx, handle, projectRoot, mcpProjectContextDeps())
	return binding, visible, err
}

func existingExposureReferenceMCP(exposures []store.ItemExposure, projectRoot string) string {
	for _, exposure := range exposures {
		if exposure.ProjectRoot == projectRoot {
			return exposure.Reference
		}
	}
	return ""
}

func appendSecretAuditMCP(eventType string, _ string, details map[string]any) {
	log, err := newMCPAuditLogFn()
	if err != nil {
		return
	}
	log = log.WithKey(auditlog.GetHMACKey())
	_, _ = log.Append(eventType, "agent", details)
}
