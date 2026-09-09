package brokerops

import (
	"context"
	"github.com/gethasp/hasp/apps/server/internal/store"
	"path/filepath"
	"testing"
)

func TestWriteEnvRechecksAfterAllThreeGrants(t *testing.T) {
	request := onceExecutionFixture(t, store.PolicySession)
	_, err := AuthorizeReference(context.Background(), request.Handle, request.BindingID, request.ProjectRoot, request.SessionToken,
		"@one", store.OperationWriteEnv, store.GrantOnce, store.GrantOnce, store.GrantOnce, 0, filepath.Join(request.ProjectRoot, ".env"))
	if err != nil {
		t.Fatalf("project, convenience, and secret grants were supplied but not rechecked: %v", err)
	}
}
