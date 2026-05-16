package mcp

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/store"
	"github.com/gethasp/hasp/apps/server/internal/testutil"
)

func TestMain(m *testing.M) {
	cleanup, err := configureMCPTestTempRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure mcp test temp root: %v\n", err)
		os.Exit(2)
	}
	restoreEnvelopeDurability := store.ConfigureEnvelopeDurabilityForTests()
	code := m.Run()
	restoreEnvelopeDurability()
	cleanup()
	os.Exit(code)
}

func configureMCPTestTempRoot() (func(), error) {
	return testutil.ConfigurePackageTempRoot("mcp")
}

func initTestGitRepo(root string) ([]byte, error) {
	return testutil.InitMinimalGitRepo(root)
}

func grantMCPProjectSession(t *testing.T, handle *store.Handle, projectRoot string, sessionToken string) {
	t.Helper()
	binding, _, err := handle.ResolveBindingView(context.Background(), projectRoot)
	if err != nil {
		t.Fatalf("resolve binding for MCP session grant: %v", err)
	}
	if binding.ID == "" {
		t.Fatalf("project %q is not bound", projectRoot)
	}
	if _, err := handle.GrantProjectLease(binding.ID, sessionToken, store.GrantSession, 0); err != nil {
		t.Fatalf("grant MCP project session: %v", err)
	}
}
