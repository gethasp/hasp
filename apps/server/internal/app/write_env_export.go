package app

import (
	"context"
	"errors"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

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
		lines = append(lines, envName+request.LineSeparator+string(item.Value))
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
