package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

// rejectLineDeliveryNewline guards line-based delivery formats (.env, xcconfig)
// where a value is written as a single `KEY<sep>VALUE` line. A newline in the
// value can't be represented in those formats and would inject an extra
// assignment (xcconfig has no escaping; a raw .env line is unquoted). Multi-line
// secrets (PEM keys, certs) must use file delivery instead. This does NOT apply
// to direct process-env injection, where a value may legitimately hold newlines.
func rejectLineDeliveryNewline(name string, value []byte) error {
	if bytes.ContainsAny(value, "\n\r") {
		return fmt.Errorf("secret %q contains a newline and cannot be delivered via a line-based env/xcconfig file; use file delivery instead", name)
	}
	return nil
}

type writeEnvExportRequest struct {
	ProjectRoot   string
	OutputPath    string
	BindingID     string
	SessionToken  string
	EnvRefs       map[string]string
	LineSeparator string
	ProjectScope  store.GrantScope
	SecretScope   store.GrantScope
	Convenience   store.GrantScope
	Window        time.Duration
}

func authorizeWriteEnvExport(ctx context.Context, handle *store.Handle, deps execDeps, request writeEnvExportRequest) ([]string, error) {
	lines := make([]string, 0, len(request.EnvRefs))
	resolvedItems := make(map[string]store.Item, len(request.EnvRefs))
	referenceSet := make([]string, 0, len(request.EnvRefs))
	for _, reference := range request.EnvRefs {
		resolved, err := deps.ResolveReference(handle, ctx, request.ProjectRoot, reference)
		if err != nil {
			return nil, err
		}
		item, err := deps.GetItem(handle, resolved.ItemName)
		if err != nil {
			return nil, err
		}
		resolvedItems[reference] = item
		referenceSet = append(referenceSet, reference)
	}
	if err := authorizeWriteEnvConvenience(handle, deps, request, referenceSet); err != nil {
		return nil, err
	}
	for envName, reference := range request.EnvRefs {
		item := resolvedItems[reference]
		item, err := deps.AuthorizeItem(handle, request.BindingID, request.SessionToken, item, store.OperationWriteEnv, request.ProjectScope, request.SecretScope, request.Window)
		if err != nil {
			return nil, err
		}
		if err := rejectLineDeliveryNewline(envName, item.Value); err != nil {
			return nil, err
		}
		lines = append(lines, envName+request.LineSeparator+string(item.Value))
	}
	// Spend the one-time convenience grant once delivery is authorized. The
	// per-item AuthorizeItem calls run with no DestinationPath/Aliases, so they
	// never match (and thus never consume) the convenience grant keyed on the
	// real output path + reference set — leaving a GrantOnce approval replayable.
	// Consume it explicitly here. No-op for session/window convenience grants.
	if deps.ConsumeConvenienceGrant != nil && len(referenceSet) > 0 {
		if err := deps.ConsumeConvenienceGrant(handle, request.BindingID, request.OutputPath, referenceSet); err != nil {
			return nil, err
		}
	}
	return lines, nil
}

func authorizeWriteEnvConvenience(handle *store.Handle, deps execDeps, request writeEnvExportRequest, referenceSet []string) error {
	if len(referenceSet) == 0 {
		return nil
	}
	decision := handle.Authorize(store.AccessRequest{
		Operation:       store.OperationWriteEnv,
		BindingID:       request.BindingID,
		SessionToken:    request.SessionToken,
		DestinationPath: request.OutputPath,
		Aliases:         referenceSet,
	})
	if !decision.RequiresPrompt {
		return nil
	}
	switch decision.RequiredAction() {
	case store.AccessRequirementProjectAndConvenience:
		if request.ProjectScope == "" {
			return errors.New("project lease required for write-env")
		}
		if _, err := deps.GrantProjectLease(handle, request.BindingID, request.SessionToken, request.ProjectScope, request.Window); err != nil {
			return err
		}
		fallthrough
	case store.AccessRequirementConvenience:
		if request.Convenience == "" {
			return errors.New("convenience approval required for write-env")
		}
		if _, err := deps.GrantConvenience(handle, request.BindingID, request.SessionToken, request.OutputPath, referenceSet, "user", request.Convenience, request.Window); err != nil {
			return err
		}
	}
	return nil
}
