package store

import (
	"fmt"
	"os"
	"testing"

	"github.com/gethasp/hasp/apps/server/internal/testutil"
)

func TestMain(m *testing.M) {
	cleanup, err := configureStoreTestTempRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure store test temp root: %v\n", err)
		os.Exit(2)
	}
	restoreEnvelopeDurability := ConfigureEnvelopeDurabilityForTests()
	code := m.Run()
	restoreEnvelopeDurability()
	cleanup()
	os.Exit(code)
}

func configureStoreTestTempRoot() (func(), error) {
	return testutil.ConfigurePackageTempRoot("store")
}
