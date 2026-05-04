package mcp

import (
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
